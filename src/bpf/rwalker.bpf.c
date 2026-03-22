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
        __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

const volatile int iter_mode = 0;

#define BPF_MAX_STACK_DEPTH 127
#define BPF_MAX_STACK_SIZE (BPF_MAX_STACK_DEPTH * sizeof(stackframe_t))

struct task_stack {
	pid_t pid;
	pid_t tgid;
	uint64_t cpu;
	uint64_t task_ptr;
	uint64_t wait_ns;
	uint64_t switch_count;
	int32_t state;
	int16_t kstack_len;
	stackframe_t kstack[BPF_MAX_STACK_DEPTH];
	u8 comm[TASK_COMM_LEN];
};

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
	bpf_probe_read_kernel_str(t->comm, TASK_COMM_LEN, task->comm);
	bpf_seq_write(seq, t, sizeof(struct task_stack));

	return 0;
}

SEC("perf_event")
int profile(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();
	struct task_stack *t;
	struct task_struct *task;
	int32_t res;
	struct rq *rq;

	rq = (struct rq *)bpf_per_cpu_ptr(&runqueues, cpu_id);
	if (rq) {
		task = bpf_get_current_task_btf();
		if (task == rq->idle)
			return 0;
	}

	t = bpf_ringbuf_reserve(&events, sizeof(*t), 0);
	if (!t)
		return 1;

	t->pid = pid;
	t->tgid = 0;
	t->task_ptr = 0;
	t->wait_ns = 0;
	t->switch_count = 0;
	t->state = 0;
	t->cpu = cpu_id;

	if (bpf_get_current_comm(t->comm, TASK_COMM_LEN))
		t->comm[0] = 0;

	res = bpf_get_stack(ctx, t->kstack, BPF_MAX_STACK_SIZE, 0);
	if (res < 0)
		res = 0;

	t->kstack_len = res / sizeof(stackframe_t);
	bpf_ringbuf_submit(t, 0);

	return 0;
}
