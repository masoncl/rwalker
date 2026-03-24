# rwalker

A BPF-based tool for diagnosing stuck tasks, CPU contention, and
off-CPU latency on Linux.  rwalker uses BPF iterators to walk kernel
task state, perf events to profile CPU usage, and sched_switch
tracepoints to measure off-CPU (blocked) time — all with symbolized
kernel and user stack traces in perf-report style output.

## Building

Requires a C compiler with BPF support (clang), libbpf headers, and a
Rust toolchain.

```
cargo build --release
```

The build compiles the BPF C program (`src/bpf/rwalker.bpf.c`) into a
skeleton that is linked into the Rust binary.  The build script
post-processes the generated bindings to work around a duplicate enum
discriminant in newer kernel headers.

## Usage

rwalker requires root (or `CAP_BPF` + `CAP_PERFMON`) to load BPF
programs and attach perf events.

### D-state task detection (default)

```
rwalker
```

Shows tasks in TASK_UNINTERRUPTIBLE (D state) or TASK_RUNNING, with
kernel stack traces and wait times.  Output includes per-task details
followed by a histogram of common stack traces.

### Stuck task detection

```
rwalker --stuck
```

Loops 5 times at 2-second intervals looking for tasks that have been in
D state for at least 1 second.  Exits as soon as stuck tasks are found.

### CPU profiling

```
rwalker -p 5
```

Profiles kernel CPU usage for 5 seconds using hardware perf events
(CPU cycles at 4000 Hz, matching `perf record` defaults).  Output is
grouped by leaf function (where the CPU was executing) with a call
chain tree showing all paths that led there — similar to
`perf report --all-kernel`.

Add `-u` to include user-space stacks (requires frame pointers in
target binaries):

```
rwalker -p 5 -u
```

### Off-CPU profiling

```
rwalker --offcpu 5
```

Measures time tasks spend blocked (waiting on I/O, locks, sleep) for
5 seconds.  Attaches to `sched_switch` to capture the kernel stack at
switch-out time, then measures the delta when the task resumes.
Events shorter than 1ms are filtered in BPF.  Output shows percentage
of total off-CPU time and absolute milliseconds per leaf function.

Add `-u` to include user-space stacks (captured at switch-out while
the process mm is still active):

```
rwalker --offcpu 5 -u
```

### Tracepoint tracing

```
rwalker --trace sched_switch:5
```

Attaches to a kernel raw tracepoint and captures stacks on every hit
for 5 seconds.  Shows which code paths trigger the tracepoint, with
the same perf-report style output as CPU profiling.

### Function tracing (kfunc)

```
rwalker --kfunc ksys_write:5
```

Attaches to a kernel function entry via BPF fentry/trampoline.  Shows
all call chains that reach the function.  Useful for tracing specific
syscalls or internal kernel functions.  Add `-u` for user stacks:

```
rwalker --kfunc ksys_write:5 -u -c myapp
```

### Options

```
Usage: rwalker [OPTIONS]

Options:
  -v, --verbose        Print function addresses as well as names
  -a, --all            Dump all task stacks (not just D/R state)
  -c, --command <CMD>  Filter on command name (accepts a regex)
  -q, --quick          Skip expensive DWARF symbolization
  -r, --running        Only print running tasks
  -s, --stuck          Loop looking for stuck D-state tasks
  -w, --waiting <N>    Only print tasks waiting longer than N seconds [default: 0]
  -i, --interval <N>   Re-read task stacks every N seconds [default: 0]
  -C, --count <N>      Stop after N iterations in interval mode [default: 0]
  -p, --profile <N>    Profile CPU usage for N seconds [default: 0]
      --offcpu <N>     Profile off-CPU (blocked) time for N seconds [default: 0]
      --trace <N:S>    Trace a raw tracepoint (e.g. sched_switch:5)
      --kfunc <N:S>    Trace a kernel function via fentry (e.g. ksys_write:5)
  -u, --user           Include user-space stacks (requires frame pointers)
  -P, --cpus <CPUS>    CPU mask for profiling (e.g. "0-3" or "1,4,7")
  -f, --freq <N>       Sampling frequency in Hz [default: 4000]
      --sw-perf        Force software CPU clock events instead of hardware PMU
  -h, --help           Print help
```

### Examples

Find tasks stuck for more than 10 seconds:
```
rwalker -w 10
```

Profile CPU 1 for 10 seconds:
```
rwalker -p 10 -P 1
```

Profile CPUs 0-7 for 5 seconds with quick symbolization:
```
rwalker -p 5 -P 0-7 -q
```

Show all tasks matching "btrfs" with full addresses:
```
rwalker -a -c btrfs -v
```

Profile with user-space stacks, filtered to a specific process:
```
rwalker -p 5 -u -c myapp
```

Find what's blocking a process:
```
rwalker --offcpu 5 -u -c myapp
```

Monitor D-state tasks every 5 seconds, 20 iterations:
```
rwalker -i 5 -C 20
```

Trace what's calling schedule:
```
rwalker --trace sched_switch:5
```

Trace write syscalls from a specific process:
```
rwalker --kfunc ksys_write:5 -u -c myapp
```

Profile in a VM without hardware PMU:
```
rwalker -p 5 --sw-perf
```

## Output

### D-state mode

Each task is printed with its comm, PID, state, wait time, and CPU,
followed by a symbolized kernel stack trace:

```
comm kworker/0:1 pid 12345 state D wait 5.23 queue CPU 0
                 rwsem_down_write_slowpath
                 btrfs_commit_transaction
                 ...
```

After individual tasks, a histogram groups tasks by common stack traces.

### Profiling mode

Output is grouped by the function consuming the most CPU, with a tree
showing all call chains that led to it:

```
>>> 22.98%  _raw_spin_lock_irqsave  Comms: some_process, some_other_process
            |
            entry_SYSCALL_64_after_hwframe+0x73 common.c:73
            do_syscall_64+0x82 common.c:52
            __x64_sys_futex+0x9a syscalls.c:160
            futex_q_lock+0x42 core.c:525
            |--15.21%--queued_spin_lock_slowpath+0x1a3 qspinlock.c:474
             --7.77%--_raw_spin_lock_irqsave+0x32 spinlock.c:162
```

Branches below 0.25% of total samples are pruned.  The `+0xNN`
offset and source location shown at each node correspond to the
instruction offset that collected the most samples.

## Architecture

```
src/
  bpf/
    rwalker.bpf.c   BPF programs (task iterator, perf_event profiler, sched_switch off-CPU, raw_tp tracer, fentry kfunc tracer)
    vmlinux.h        Kernel type definitions for BPF CO-RE
  main.rs            CLI, task walking, profiling output, call tree display
  profile.rs         Profiler: perf event setup, ringbuf consumption, stack aggregation
  task.rs            Task struct: state decoding, wait time tracking, stack extraction
  syscall.rs         perf_event_open syscall wrapper and perf_event_attr definition
  cpumask.rs         CPU mask string parser (e.g. "0-3,7")
  skel.rs            Generated BPF skeleton include wrapper
build.rs             Build script: BPF compilation via libbpf-cargo
```

### BPF programs

**`get_task_stacks`** (iter/task) -- Iterates all kernel tasks, filters
by state (D-state, running, or all), collects kernel stack traces via
`bpf_get_task_stack()`, and writes results through `bpf_seq_write()`.
Uses BPF CO-RE for portability across kernel versions (pre/post 5.14
task state field, `sched_info.run_delay` with field existence check).

**`profile`** (perf_event) -- Attached to hardware CPU cycle perf events.
Skips idle tasks by comparing against the per-CPU runqueue idle task.
Captures kernel and user stacks via `bpf_get_stack()` and submits
through a 32MB ringbuf.  Uses BTF task_struct reads for init-namespace
PIDs (container-safe).

**`offcpu_switch`** (tp_btf/sched_switch) -- Measures off-CPU time by
recording switch-out timestamps and user stacks in a per-pid hash map,
then computing the delta at switch-in.  Events below 1ms are filtered
in BPF.  Kernel stacks are captured fresh at switch-in; user stacks
are replayed from switch-out (when the process mm was still active).

**`trace_event`** (raw_tp) -- Generic tracepoint tracer.  Attached to
any raw tracepoint by name at runtime.  Captures kernel and user
stacks on every hit.

**`kfunc_event`** (fentry) -- Function entry tracer via BPF
trampoline.  The target function is set at runtime via
`set_attach_target()` before loading.  Captures kernel and user
stacks on every call to the target function.

### Rust components

**Profiler** manages perf event lifecycle: opens perf events per CPU,
attaches the BPF program, builds a ringbuf consumer.  Used for both
on-CPU and off-CPU modes.  Raw stacks are aggregated in a
`HashMap<ProfileFrame, StackCounter>` keyed by (pid, addresses).

**Call tree display** symbolizes raw stacks to function names, groups by
leaf function, builds a `CallTreeNode` trie from root caller to leaf,
and prints with branching percentages at divergence points.  Each node
tracks per-offset hit counts to display the most common instruction
offset and source location.  Symbolization is batched and cached:
leaf addresses are resolved first to filter by 0.25% threshold before
full-stack symbolization, and a per-address cache avoids redundant
blazesym calls.  User stacks from frame-pointer-less binaries are
trimmed.  `.gnu_debugdata` (MiniDebugInfo) is supported via the
blazesym xz feature.

## Dependencies

- [libbpf-rs](https://github.com/libbpf/libbpf-rs) -- BPF program loading and map interaction
- [libbpf-cargo](https://github.com/libbpf/libbpf-rs) -- BPF skeleton generation at build time
- [blazesym](https://github.com/libbpf/blazesym) -- Kernel address symbolization with DWARF support
- [clap](https://github.com/clap-rs/clap) -- Command line argument parsing
- [plain](https://crates.io/crates/plain) -- Safe transmute for C struct deserialization
- [chrono](https://github.com/chronotope/chrono) -- Timestamp formatting
- [regex](https://github.com/rust-lang/regex) -- Command name filtering
- [anyhow](https://github.com/dtolnay/anyhow) -- Error handling

## License

Dual BSD/GPL (matching the BPF program license).
