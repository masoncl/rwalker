#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_RUNNING 0x00000000
#define TASK_INTERRUPTIBLE 0x00000001
#define TASK_UNINTERRUPTIBLE 0x00000002
#define TASK_NOLOAD 0x00000400

#define NSEC_TO_SEC (1000000000)

extern u32 CONFIG_HZ __kconfig;

typedef uint64_t stackframe_t;
enum {
	ITER_MODE_DSTATE = 0,
	ITER_MODE_RUNNING = 1,
	ITER_MODE_ALL = 2,
};

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 32 * 1024 * 1024);
} events SEC(".maps");

const volatile int iter_mode = 0;
const volatile uint64_t offcpu_min_ns = 1000000; /* 1ms default threshold */
const volatile int dwarf_mode = 0;

#define BPF_MAX_STACK_DEPTH 127
#define BPF_MAX_STACK_SIZE (BPF_MAX_STACK_DEPTH * sizeof(stackframe_t))
#define DWARF_STACK_SIZE 32768 /* 32KB to capture deep user stacks */

struct task_stack {
	pid_t pid;
	pid_t tgid;
	uint64_t cpu;
	uint64_t task_ptr;
	uint64_t wait_ns;
	uint64_t switch_count;
	int32_t state;
	int16_t kstack_len;
	int16_t ustack_len;
	stackframe_t kstack[BPF_MAX_STACK_DEPTH];
	stackframe_t ustack[BPF_MAX_STACK_DEPTH];
	u8 comm[TASK_COMM_LEN];
};

struct dwarf_sample {
	struct task_stack ts;
	uint64_t user_regs[3]; /* RIP, RSP, RBP */
	uint32_t stack_len;
	uint8_t user_stack[DWARF_STACK_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024 * 1024);
} dwarf_events SEC(".maps");

struct task_struct___post514 {
	unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___pre514 {
	long state;
} __attribute__((preserve_access_index));

static void copy_state(void *arg, struct task_stack *t)
{
	if (bpf_core_field_exists(struct task_struct___pre514, state)) {
		struct task_struct___pre514 *task = arg;
		t->state = task->state;
	} else {
		struct task_struct___post514 *task = arg;
		t->state = task->__state;
	}
}
static void copy_wait_time(struct task_struct *task, struct task_stack *t)
{
	t->wait_ns = 0;
	t->task_ptr = (uint64_t)task;
	t->switch_count = task->nvcsw + task->nivcsw;

	if (t->state == TASK_UNINTERRUPTIBLE) {
		uint64_t switch_count = task->nvcsw + task->nivcsw;
		uint64_t now = bpf_jiffies64();
		if (now > task->last_switch_time &&
		    switch_count == task->last_switch_count) {
			t->wait_ns = now - task->last_switch_time;
			t->wait_ns = t->wait_ns * (NSEC_TO_SEC / CONFIG_HZ);
		}
	}
}

static int32_t write_task_stack(struct task_struct *task, stackframe_t *stack,
				uint64_t flags)
{
	int32_t res;
	res = bpf_get_task_stack(task, stack, BPF_MAX_STACK_SIZE, flags);

	if (res < 0) {
		return 0;
	}
	return res / sizeof(stackframe_t);
}

extern const struct rq runqueues __ksym; /* struct type global var. */

// needs to be static due to stack size limitiations
struct task_stack task_stack_buf = { 0 };

SEC("iter/task")
int get_task_stacks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (task == (void *)0) {
		return 0;
	}

	struct task_stack *t = &task_stack_buf;

	copy_state(task, t);

	switch (iter_mode) {
	case ITER_MODE_DSTATE:
		// in DSTATE mode we want UNINTERRUPTIBLE, or running tasks, and
		// we don't want NOLOAD tasks
		if ((t->state & TASK_NOLOAD) ||
		    !((t->state & TASK_UNINTERRUPTIBLE) ||
		      t->state == TASK_RUNNING))
			return 0;
		break;
	case ITER_MODE_RUNNING:
		// only TASK_RUNNING
		if (t->state != TASK_RUNNING)
			return 0;
		break;
	case ITER_MODE_ALL:
		// just all the tasks
		break;
	default:
		// invalid mode, make the user try again
		return -1;
	}

	copy_wait_time(task, t);

	t->pid = task->pid;
	t->tgid = task->tgid;
	t->cpu = BPF_CORE_READ(task, wake_cpu);

	t->kstack_len = write_task_stack(task, t->kstack, 0);
	t->ustack_len = 0;
	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, task->comm);
	bpf_seq_write(seq, t, sizeof(struct task_stack));

	return 0;
}

/* Max user frames saved at switch-out for off-CPU profiling.
 * Kept smaller than BPF_MAX_STACK_DEPTH to limit hash map memory.
 */
#define OFFCPU_MAX_USTACK 32
#define OFFCPU_USTACK_SIZE (OFFCPU_MAX_USTACK * sizeof(stackframe_t))

struct offcpu_val {
	u64 timestamp;
	pid_t tgid;            /* init-ns process ID (for symbolization) */
	int16_t ustack_len;
	stackframe_t ustack[OFFCPU_MAX_USTACK];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);      /* keyed by kernel pid (tid) */
	__type(value, struct offcpu_val);
} offcpu_start SEC(".maps");

SEC("tp_btf/sched_switch")
int offcpu_switch(u64 *ctx)
{
	/* tp_btf/sched_switch args: bool preempt, struct task_struct *prev,
	 *                           struct task_struct *next, unsigned int prev_state
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	u64 now = bpf_ktime_get_ns();
	u32 prev_pid = prev->pid;
	u32 next_pid = next->pid;

	/* Record switch-out: capture timestamp and user stack from prev
	 * while its mm is still active.
	 */
	if (prev_pid != 0) {
		struct offcpu_val val = {};
		int32_t res;

		val.timestamp = now;
		val.tgid = prev->tgid;

		res = bpf_get_task_stack(prev, val.ustack,
					OFFCPU_USTACK_SIZE, BPF_F_USER_STACK);
		if (res < 0)
			res = 0;
		val.ustack_len = res / sizeof(stackframe_t);

		bpf_map_update_elem(&offcpu_start, &prev_pid, &val, BPF_ANY);
	}

	/* On switch-in, compute off-CPU time for next */
	if (next_pid == 0)
		return 0;

	struct offcpu_val *stored = bpf_map_lookup_elem(&offcpu_start, &next_pid);
	if (!stored)
		return 0;

	u64 delta = now - stored->timestamp;

	if (delta < offcpu_min_ns) {
		bpf_map_delete_elem(&offcpu_start, &next_pid);
		return 0;
	}

	struct task_stack *t = bpf_ringbuf_reserve(&events, sizeof(*t), 0);
	if (!t) {
		bpf_map_delete_elem(&offcpu_start, &next_pid);
		return 0;
	}

	t->pid = stored->tgid;  /* init-ns process ID */
	t->tgid = next_pid;     /* init-ns thread ID */
	t->task_ptr = 0;
	t->wait_ns = delta;
	t->switch_count = 0;
	t->state = 0;
	t->cpu = bpf_get_smp_processor_id();

	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, next->comm);

	/* Kernel stack: captured fresh from next (its kernel stack is valid) */
	t->kstack_len = write_task_stack(next, t->kstack, 0);

	/* User stack: replay what we saved at switch-out time */
	int16_t ulen = stored->ustack_len;
	if (ulen > BPF_MAX_STACK_DEPTH)
		ulen = BPF_MAX_STACK_DEPTH;
	t->ustack_len = ulen;
	/* bpf_probe_read_kernel for the stored ustack */
	if (ulen > 0)
		bpf_probe_read_kernel(t->ustack, ulen * sizeof(stackframe_t),
				      stored->ustack);

	bpf_map_delete_elem(&offcpu_start, &next_pid);
	bpf_ringbuf_submit(t, 0);
	return 0;
}

/* Submit a dwarf sample: task_stack (kernel stack only) + raw user
 * stack dump + registers.  Called from profile/trace/kfunc when
 * dwarf_mode is enabled.
 */
static __always_inline int submit_dwarf_sample(struct task_struct *task)
{
	struct dwarf_sample *ds;
	struct pt_regs *regs;
	int32_t res;

	ds = bpf_ringbuf_reserve(&dwarf_events, sizeof(*ds), 0);
	if (!ds)
		return 0;

	ds->ts.pid = task->tgid;
	ds->ts.tgid = task->pid;
	ds->ts.task_ptr = 0;
	ds->ts.wait_ns = 0;
	ds->ts.switch_count = 0;
	ds->ts.state = 0;
	ds->ts.cpu = bpf_get_smp_processor_id();

	if (bpf_get_current_comm(ds->ts.comm, TASK_COMM_LEN))
		ds->ts.comm[0] = 0;

	/* Kernel stack — use bpf_get_task_stack instead of bpf_get_stack
	 * so this works in fentry/raw_tp context where ctx is not pt_regs.
	 */
	ds->ts.kstack_len = write_task_stack(task, ds->ts.kstack, 0);
	ds->ts.ustack_len = 0;

	/* User registers from pt_regs */
	regs = (struct pt_regs *)bpf_task_pt_regs(task);
	if (regs) {
		ds->user_regs[0] = BPF_CORE_READ(regs, ip);
		ds->user_regs[1] = BPF_CORE_READ(regs, sp);
		ds->user_regs[2] = BPF_CORE_READ(regs, bp);
	} else {
		ds->user_regs[0] = 0;
		ds->user_regs[1] = 0;
		ds->user_regs[2] = 0;
	}

	/* Raw user stack dump */
	if (ds->user_regs[1]) {
		res = bpf_probe_read_user(ds->user_stack, DWARF_STACK_SIZE,
					  (void *)ds->user_regs[1]);
		ds->stack_len = (res == 0) ? DWARF_STACK_SIZE : 0;
	} else {
		ds->stack_len = 0;
	}

	bpf_ringbuf_submit(ds, 0);
	return 0;
}

/* Common logic for kfunc/trace/profile: submit to normal ringbuf
 * with frame-pointer user stacks, or to dwarf ringbuf with raw
 * stack dump.
 */
static __always_inline int submit_sample(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct task_stack *t;
	int32_t res;

	if (dwarf_mode)
		return submit_dwarf_sample(task);

	t = bpf_ringbuf_reserve(&events, sizeof(*t), 0);
	if (!t)
		return 0;

	t->pid = task->tgid;
	t->tgid = task->pid;
	t->task_ptr = 0;
	t->wait_ns = 0;
	t->switch_count = 0;
	t->state = 0;
	t->cpu = bpf_get_smp_processor_id();

	if (bpf_get_current_comm(t->comm, TASK_COMM_LEN))
		t->comm[0] = 0;

	res = bpf_get_stack(ctx, t->kstack, BPF_MAX_STACK_SIZE, 0);
	if (res < 0)
		res = 0;
	t->kstack_len = res / sizeof(stackframe_t);

	res = bpf_get_stack(ctx, t->ustack, BPF_MAX_STACK_SIZE, BPF_F_USER_STACK);
	if (res < 0)
		res = 0;
	t->ustack_len = res / sizeof(stackframe_t);

	bpf_ringbuf_submit(t, 0);
	return 0;
}

SEC("fentry")
int kfunc_event(void *ctx)
{
	return submit_sample(ctx);
}

SEC("raw_tp")
int trace_event(void *ctx)
{
	return submit_sample(ctx);
}

SEC("perf_event")
int profile(void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	int cpu_id = bpf_get_smp_processor_id();
	struct rq *rq;

	rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, cpu_id);
	if (rq) {
		if (task == rq->idle)
			return 0;
	}

	return submit_sample(ctx);
}
