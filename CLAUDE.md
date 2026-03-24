# Development Guide

## Build verification

After every change, run:
```
cargo fmt ; cargo clippy ; cargo build --release
```
All three must pass with no errors or warnings.

## Build system

The BPF C program (`src/bpf/rwalker.bpf.c`) is compiled into a Rust skeleton by `build.rs` using libbpf-cargo. The generated skel lands in `$OUT_DIR/rwalker.skel.rs` and is included via `src/skel.rs`. Changing the BPF C struct layout (e.g. `struct task_stack`) automatically regenerates the Rust bindings — no manual sync needed.

`build.rs` patches the generated bindings to remove a duplicate enum discriminant (`BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED`) that is valid C but not Rust.

## Key struct: `task_stack`

Defined in `src/bpf/rwalker.bpf.c` and auto-generated into Rust. Shared between the BPF iterator (`get_task_stacks`) and the perf profiler (`profile`). The iterator does not populate user stack fields — always set `ustack_len = 0` explicitly in that path since the global buffer is reused across calls.

## Testing

Requires root (or `CAP_BPF` + `CAP_PERFMON`). No unit test suite — verify manually:

- D-state walking: `sudo ./target/release/rwalker`
- Off-CPU profiling: `sudo ./target/release/rwalker --offcpu 5`
- Kernel profiling: `sudo ./target/release/rwalker -p 5`
- User+kernel profiling: `sudo ./target/release/rwalker -p 5 -u` (requires frame pointers in target binaries)
- Quick mode (skip DWARF): `sudo ./target/release/rwalker -p 5 -q`

## Profiler architecture

Perf events are opened per-CPU via raw `perf_event_open` syscall (`src/syscall.rs`). The BPF `profile` program is attached to each perf event fd. Samples flow through a ringbuf map, consumed by `Profiler::poll()`. Raw address stacks are aggregated in a `HashMap<ProfileFrame, StackCounter>`.

Symbolization uses blazesym (pinned to 0.2.3): `Source::Kernel` for kernel frames, `Source::Process` for userspace frames (keyed by tgid/pid). The BPF ksym resolver (`BpfKsymResolver`) handles BPF JIT addresses that blazesym misresolves through vmlinux.

## Common gotchas

- blazesym is pinned (`=0.2.3`) — do not bump without checking API compatibility
- The `perf_event_attr` struct in `syscall.rs` is a manual definition matching the kernel UAPI — field order and sizes matter
- Hardware PMU may not be available in VMs; the profiler auto-falls back to software CPU clock (`--sw-perf` forces it)
- Ringbuf is 32MB; at high frequencies with many CPUs, samples may be dropped silently (bpf_ringbuf_reserve returns NULL)
