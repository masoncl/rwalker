use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;
use std::mem;

use crate::skel::rwalker::types::task_stack;
use crate::skel::rwalker::RwalkerSkel;
use libbpf_rs::RingBuffer;
use std::cell::RefCell;
use std::rc::Rc;

use std::io;

use anyhow::Context;

use crate::skel::BPF_MAX_STACK_DEPTH;
use crate::syscall;

// Raw stack frame keyed by addresses only (not CPU).  The tree grouping
// merges across CPUs by function name, so separating by CPU here would
// just inflate the map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileFrame {
    pub frame: Vec<u64>,
}

impl ProfileFrame {
    pub fn new(frame: [u64; BPF_MAX_STACK_DEPTH], frame_len: i16) -> Self {
        ProfileFrame {
            frame: frame[..frame_len as usize].to_vec(),
        }
    }
}

// For profiling, we just record the stacks
pub struct StackCounter {
    pub hits: u64,
    pub comms: HashSet<[u8; crate::skel::TASK_COMM_LEN]>,
}

impl StackCounter {
    pub fn new() -> StackCounter {
        StackCounter {
            hits: 0,
            comms: HashSet::new(),
        }
    }
    pub fn add(&mut self, comm: [u8; crate::skel::TASK_COMM_LEN]) {
        self.hits += 1;
        self.comms.insert(comm);
    }
}

pub type StackMap = Rc<RefCell<HashMap<ProfileFrame, StackCounter>>>;

fn event_handler(
    total_events: &Rc<RefCell<u64>>,
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

    if event.kstack_len <= 0 {
        return 0;
    }

    let frame = ProfileFrame::new(event.kstack, event.kstack_len);

    *total_events.borrow_mut() += 1;

    let mut map = perf_stack_map.borrow_mut();
    let val = map.entry(frame).or_insert(StackCounter::new());
    val.add(event.comm);
    0
}

pub struct Profiler<'a> {
    pub perf_stack_map: StackMap,
    pub total_events: Rc<RefCell<u64>>,

    ringbuf: Option<RingBuffer<'a>>,
    pefds: Option<Vec<i32>>,
    links: Option<Vec<libbpf_rs::Link>>,
    cpus_to_profile: Option<Vec<u32>>,
}

impl<'a> Profiler<'a> {
    pub fn new(cpus_to_profile: Option<Vec<u32>>) -> Self {
        Profiler {
            perf_stack_map: Rc::new(RefCell::new(HashMap::new())),
            total_events: Rc::new(RefCell::new(0)),
            ringbuf: None,
            pefds: None,
            links: None,
            cpus_to_profile,
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

    fn init_perf_monitor(&self, freq: u64, force_sw: bool) -> Result<Vec<i32>, anyhow::Error> {
        let nprocs = libbpf_rs::num_possible_cpus().unwrap();
        let mut attr = Box::new(unsafe { mem::zeroed::<syscall::perf_event_attr>() });

        let default_cpus: Vec<u32> = (0..nprocs as u32).collect();
        let cpus = self.cpus_to_profile.as_ref().unwrap_or(&default_cpus);

        attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
        attr.sample.sample_freq = freq;
        attr.flags = syscall::PERF_ATTR_FLAG_FREQ
            | syscall::PERF_ATTR_FLAG_EXCLUDE_USER
            | syscall::PERF_ATTR_FLAG_EXCLUDE_GUEST;

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

    pub fn setup(
        &mut self,
        skel: &'a RwalkerSkel<'a>,
        freq: u64,
        force_sw: bool,
    ) -> Result<(), anyhow::Error> {
        let map = self.perf_stack_map.clone();
        let events = self.total_events.clone();

        self.pefds = Some(Profiler::<'a>::init_perf_monitor(self, freq, force_sw)?);
        self.links = Some(Profiler::<'a>::attach_perf_event(
            self.pefds.as_ref().unwrap(),
            &skel.progs.profile,
        )?);

        let mut builder = libbpf_rs::RingBufferBuilder::new();

        builder
            .add(&skel.maps.events, move |data| {
                event_handler(&events, &map, data)
            })
            .unwrap();

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
    pub fn reset_frames(&mut self) {
        let mut map = self.perf_stack_map.borrow_mut();
        map.clear();
        *self.total_events.borrow_mut() = 0;
    }
}
