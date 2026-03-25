use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;
use std::mem;

use crate::dwarf_unwind::DwarfUnwinder;
use crate::skel::rwalker::types::task_stack;
use crate::skel::rwalker::RwalkerSkel;
use libbpf_rs::RingBuffer;
use std::cell::RefCell;
use std::rc::Rc;

use std::io;

use anyhow::Context;

use crate::skel::BPF_MAX_STACK_DEPTH;
use crate::syscall;

// Raw stack frame keyed by addresses and pid.  The tree grouping
// merges across CPUs by function name, so separating by CPU here would
// just inflate the map.  pid is included because the same virtual address
// in different processes maps to different functions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileFrame {
    pub pid: i32,
    pub kframe: Vec<u64>,
    pub uframe: Vec<u64>,
}

impl ProfileFrame {
    pub fn new(
        pid: i32,
        kstack: [u64; BPF_MAX_STACK_DEPTH],
        kstack_len: i16,
        ustack: [u64; BPF_MAX_STACK_DEPTH],
        ustack_len: i16,
    ) -> Self {
        ProfileFrame {
            pid,
            kframe: kstack[..kstack_len as usize].to_vec(),
            uframe: ustack[..ustack_len as usize].to_vec(),
        }
    }

    /// The innermost frame address (where the CPU was executing).
    /// Kernel leaf if available, otherwise user leaf.
    pub fn leaf_addr(&self) -> u64 {
        self.kframe
            .first()
            .or(self.uframe.first())
            .copied()
            .unwrap_or(0)
    }
}

// For profiling, we just record the stacks
pub struct StackCounter {
    pub hits: u64,
    pub total_ns: u64,
    pub comms: HashSet<[u8; crate::skel::TASK_COMM_LEN]>,
}

impl StackCounter {
    pub fn new() -> StackCounter {
        StackCounter {
            hits: 0,
            total_ns: 0,
            comms: HashSet::new(),
        }
    }
    pub fn add(&mut self, comm: [u8; crate::skel::TASK_COMM_LEN], wait_ns: u64) {
        self.hits += 1;
        self.total_ns += wait_ns;
        self.comms.insert(comm);
    }
}

pub type StackMap = Rc<RefCell<HashMap<ProfileFrame, StackCounter>>>;

fn event_handler(
    total_events: &Rc<RefCell<u64>>,
    total_ns: &Rc<RefCell<u64>>,
    perf_stack_map: &StackMap,
    data: &[u8],
) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<task_stack>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<task_stack>()
        );
        return 0;
    }

    let event = unsafe { &*(data.as_ptr() as *const task_stack) };

    if event.kstack_len <= 0 && event.ustack_len <= 0 {
        return 0;
    }

    // Use event.pid (= kernel tgid = userspace PID) for process
    // identification, not event.tgid (= kernel pid = thread ID).
    // This ensures threads from the same process share one Process
    // source and one /proc/<pid>/maps parse in blazesym.
    let frame = ProfileFrame::new(
        event.pid,
        event.kstack,
        event.kstack_len,
        event.ustack,
        event.ustack_len,
    );

    *total_events.borrow_mut() += 1;
    *total_ns.borrow_mut() += event.wait_ns;

    let mut map = perf_stack_map.borrow_mut();
    let val = map.entry(frame).or_insert(StackCounter::new());
    val.add(event.comm, event.wait_ns);
    0
}

/// Raw dwarf sample stored for deferred unwinding
pub struct RawDwarfSample {
    pub pid: i32,
    pub kstack: [u64; BPF_MAX_STACK_DEPTH],
    pub kstack_len: i16,
    pub comm: [u8; crate::skel::TASK_COMM_LEN],
    pub wait_ns: u64,
    pub user_regs: [u64; 3],
    pub user_stack: Vec<u8>,
}

pub type DwarfSamples = Rc<RefCell<Vec<RawDwarfSample>>>;

const DWARF_STACK_SIZE: usize = 16384;

/// Layout must match struct dwarf_sample in rwalker.bpf.c
#[repr(C)]
struct DwarfSample {
    ts: task_stack,
    user_regs: [u64; 3],
    stack_len: u32,
    user_stack: [u8; DWARF_STACK_SIZE],
}

fn dwarf_event_handler(
    total_events: &Rc<RefCell<u64>>,
    total_ns: &Rc<RefCell<u64>>,
    dwarf_samples: &DwarfSamples,
    data: &[u8],
) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<DwarfSample>() {
        return 0;
    }

    let sample = unsafe { &*(data.as_ptr() as *const DwarfSample) };

    if sample.ts.kstack_len <= 0 && sample.user_regs[0] == 0 {
        return 0;
    }

    *total_events.borrow_mut() += 1;
    *total_ns.borrow_mut() += sample.ts.wait_ns;

    let stack_len = (sample.stack_len as usize).min(DWARF_STACK_SIZE);
    dwarf_samples.borrow_mut().push(RawDwarfSample {
        pid: sample.ts.pid,
        kstack: sample.ts.kstack,
        kstack_len: sample.ts.kstack_len,
        comm: sample.ts.comm,
        wait_ns: sample.ts.wait_ns,
        user_regs: sample.user_regs,
        user_stack: sample.user_stack[..stack_len].to_vec(),
    });

    0
}

pub struct Profiler<'a> {
    pub perf_stack_map: StackMap,
    pub total_events: Rc<RefCell<u64>>,
    pub total_ns: Rc<RefCell<u64>>,
    pub dwarf_samples: DwarfSamples,

    ringbuf: Option<RingBuffer<'a>>,
    pefds: Option<Vec<i32>>,
    links: Option<Vec<libbpf_rs::Link>>,
    cpus_to_profile: Option<Vec<u32>>,
    dwarf: bool,
}

impl<'a> Profiler<'a> {
    pub fn new(cpus_to_profile: Option<Vec<u32>>) -> Self {
        Profiler {
            perf_stack_map: Rc::new(RefCell::new(HashMap::new())),
            total_events: Rc::new(RefCell::new(0)),
            total_ns: Rc::new(RefCell::new(0)),
            dwarf_samples: Rc::new(RefCell::new(Vec::new())),
            ringbuf: None,
            pefds: None,
            links: None,
            cpus_to_profile,
            dwarf: false,
        }
    }
    fn try_open_perf_events(
        attr: &syscall::perf_event_attr,
        cpus: &[u32],
    ) -> Result<Vec<i32>, anyhow::Error> {
        cpus.iter()
            .map(|cpu| {
                let fd = syscall::perf_event_open(attr, -1, *cpu as i32, -1, 0) as i32;
                if fd == -1 {
                    Err(anyhow::Error::from(io::Error::last_os_error()))
                        .context(format!("failed to open perf event on CPU {}", cpu))
                } else {
                    Ok(fd)
                }
            })
            .collect()
    }

    fn init_perf_monitor(
        &self,
        freq: u64,
        force_sw: bool,
        user: bool,
    ) -> Result<Vec<i32>, anyhow::Error> {
        let nprocs = libbpf_rs::num_possible_cpus().unwrap();
        let mut attr = Box::new(unsafe { mem::zeroed::<syscall::perf_event_attr>() });

        let default_cpus: Vec<u32> = (0..nprocs as u32).collect();
        let cpus = self.cpus_to_profile.as_ref().unwrap_or(&default_cpus);

        // Clamp frequency to kernel's max to avoid EINVAL — the kernel
        // auto-tunes this value downward under load.
        let max_freq = std::fs::read_to_string("/proc/sys/kernel/perf_event_max_sample_rate")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(freq);
        let actual_freq = std::cmp::min(freq, max_freq);
        if actual_freq < freq {
            eprintln!(
                "Clamping frequency from {} to {} Hz (kernel perf_event_max_sample_rate)",
                freq, actual_freq
            );
        }

        attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
        attr.sample.sample_freq = actual_freq;
        attr.flags = syscall::PERF_ATTR_FLAG_FREQ | syscall::PERF_ATTR_FLAG_EXCLUDE_GUEST;
        if !user {
            attr.flags |= syscall::PERF_ATTR_FLAG_EXCLUDE_USER;
        }

        if !force_sw {
            // Try hardware CPU cycles first (best accuracy)
            attr._type = syscall::PERF_TYPE_HARDWARE;
            attr.config = syscall::PERF_COUNT_HW_CPU_CYCLES;
            if let Ok(fds) = Self::try_open_perf_events(&attr, cpus) {
                return Ok(fds);
            }
            eprintln!("Hardware PMU not available, falling back to software CPU clock");
        }

        // Software CPU clock (works in VMs without PMU)
        attr._type = syscall::PERF_TYPE_SOFTWARE;
        attr.config = syscall::PERF_COUNT_SW_CPU_CLOCK;
        Self::try_open_perf_events(&attr, cpus)
    }

    fn attach_perf_event(
        pefds: &[i32],
        prog: &libbpf_rs::ProgramMut,
    ) -> Result<Vec<libbpf_rs::Link>, anyhow::Error> {
        pefds
            .iter()
            .map(|pefd| {
                prog.attach_perf_event(*pefd)
                    .map_err(anyhow::Error::from)
                    .context(format!("failed to attach perf event fd {}", pefd))
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        &mut self,
        skel: &'a RwalkerSkel<'a>,
        freq: u64,
        force_sw: bool,
        user: bool,
        offcpu: bool,
        tracepoint_name: Option<String>,
        kfunc: bool,
        dwarf: bool,
    ) -> Result<(), anyhow::Error> {
        let map = self.perf_stack_map.clone();
        let events = self.total_events.clone();
        let ns = self.total_ns.clone();

        if let Some(ref tp_name) = tracepoint_name {
            // raw_tp programs are attached by name, not via perf events
            let link = skel
                .progs
                .trace_event
                .attach_raw_tracepoint(tp_name)
                .context(format!("failed to attach raw tracepoint '{tp_name}'"))?;
            self.links = Some(vec![link]);
        } else if kfunc {
            // fentry program — attach target was set before load,
            // just call attach() to create the link
            let link = skel
                .progs
                .kfunc_event
                .attach()
                .context("failed to attach kfunc")?;
            self.links = Some(vec![link]);
        } else if !offcpu {
            self.pefds = Some(Profiler::<'a>::init_perf_monitor(
                self, freq, force_sw, user,
            )?);
            self.links = Some(Profiler::<'a>::attach_perf_event(
                self.pefds.as_ref().unwrap(),
                &skel.progs.profile,
            )?);
        }
        // offcpu mode: the offcpu_switch program is attached via
        // skel.attach() — we just need the ringbuf consumer here.

        let mut builder = libbpf_rs::RingBufferBuilder::new();

        self.dwarf = dwarf;
        if dwarf {
            let samples = self.dwarf_samples.clone();
            builder
                .add(&skel.maps.dwarf_events, move |data| {
                    dwarf_event_handler(&events, &ns, &samples, data)
                })
                .unwrap();
        } else {
            builder
                .add(&skel.maps.events, move |data| {
                    event_handler(&events, &ns, &map, data)
                })
                .unwrap();
        }

        self.ringbuf = Some(builder.build().unwrap());
        Ok(())
    }

    pub fn poll(&mut self, timeout: std::time::Duration) {
        let _ = self.ringbuf.as_ref().unwrap().poll(timeout);
    }

    pub fn close(&mut self) {
        // Drop links first — libbpf detaches the BPF program and closes
        // the perf event fds (close_on_destroy=true).  Do NOT manually
        // close the fds afterwards or we'll double-close.
        self.links.take();
        self.ringbuf.take();
        self.pefds.take();
    }
    /// Unwind deferred dwarf samples and merge into the perf_stack_map.
    /// Deduplicates by (pid, RIP, RSP) — samples with the same user
    /// register state produce the same unwind, so we only unwind each
    /// unique state once.
    pub fn unwind_dwarf_samples(&mut self) {
        if !self.dwarf {
            return;
        }

        let samples = self.dwarf_samples.borrow();

        // Group samples by (pid, RIP, RSP) — same user register state
        // means same unwind result.  Accumulate hits and collect the
        // kernel stacks + comms for each group.
        struct DwarfGroup {
            hits: u64,
            wait_ns: u64,
            pid: i32,
            regs: [u64; 3],
            stack: Vec<u8>,
            // representative kernel stack + comms
            kstack: [u64; BPF_MAX_STACK_DEPTH],
            kstack_len: i16,
            comms: HashSet<[u8; crate::skel::TASK_COMM_LEN]>,
        }

        let mut groups: HashMap<(i32, u64, u64), DwarfGroup> = HashMap::new();
        for sample in samples.iter() {
            let key = (sample.pid, sample.user_regs[0], sample.user_regs[1]);
            let group = groups.entry(key).or_insert_with(|| DwarfGroup {
                hits: 0,
                wait_ns: 0,
                pid: sample.pid,
                regs: sample.user_regs,
                stack: sample.user_stack.clone(),
                kstack: sample.kstack,
                kstack_len: sample.kstack_len,
                comms: HashSet::new(),
            });
            group.hits += 1;
            group.wait_ns += sample.wait_ns;
            group.comms.insert(sample.comm);
        }

        // Sort by hits (heaviest first), cap at 500 unwinds
        let mut sorted_groups: Vec<_> = groups.values().collect();
        sorted_groups.sort_by(|a, b| b.hits.cmp(&a.hits));
        sorted_groups.truncate(500);

        let mut unwinder = DwarfUnwinder::new();
        let mut map = self.perf_stack_map.borrow_mut();

        for group in sorted_groups {
            let uframes = unwinder.unwind(
                group.pid,
                group.regs[0],
                group.regs[1],
                group.regs[2],
                &group.stack,
            );

            let mut ustack = [0u64; BPF_MAX_STACK_DEPTH];
            let ustack_len = uframes.len().min(BPF_MAX_STACK_DEPTH);
            ustack[..ustack_len].copy_from_slice(&uframes[..ustack_len]);

            let frame = ProfileFrame::new(
                group.pid,
                group.kstack,
                group.kstack_len,
                ustack,
                ustack_len as i16,
            );

            let val = map.entry(frame).or_insert(StackCounter::new());
            val.hits += group.hits;
            val.total_ns += group.wait_ns;
            val.comms.extend(&group.comms);
        }
    }

    pub fn reset_frames(&mut self) {
        let mut map = self.perf_stack_map.borrow_mut();
        map.clear();
        self.dwarf_samples.borrow_mut().clear();
        *self.total_events.borrow_mut() = 0;
        *self.total_ns.borrow_mut() = 0;
    }
}
