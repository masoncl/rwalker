use plain::Plain;
use std::ffi::CStr;
use std::time::Instant;

use crate::skel::rwalker::types::task_stack;

const TASK_RUNNING: u64 = 0x00000000;
const TASK_INTERRUPTIBLE: u64 = 0x00000001;
const TASK_UNINTERRUPTIBLE: u64 = 0x00000002;
const TASK_NOLOAD: u64 = 0x00000400;
// our iterator returns times from the kernel in ns
const NSEC_PER_SEC: u64 = 1000000000;

// a kernel stack trace and details on context switch count and the timestamp
// of the last switch.
#[derive(Clone, Copy)]
pub struct Task {
    // straight from the iterator
    pub ts: task_stack,
    // voluntary and involuntary switch count as reported by the kernel
    pub last_switch_count: u64,
    // sadly not from the kernel, we have to calculate this here
    pub last_switch_time: Instant,
    // time since the last switch
    pub wait_time: f64,
    // used to expire old entries from the task/pid map
    pub dead: bool,
}
//
// struct task_stack is foreign, so I can't just implement plan for it here
// This does a dance for CopyTaskStack that lets me implement plain and
// then use copy_from_bytes()
#[allow(non_camel_case_types)]
#[derive(Clone, Default, Debug)]
pub struct CopyTaskStack(task_stack);
unsafe impl Plain for CopyTaskStack {}

impl Task {
    // we initialize a task using the buffer from the iterator
    // the buffer needs to be exactly the same size as the task_stack
    // structure
    pub fn new(buffer: &[u8; std::mem::size_of::<task_stack>()]) -> Task {
        let mut task = CopyTaskStack::default();
        task.copy_from_bytes(buffer)
            .expect("Failed to copy from bytes");
        Task {
            ts: task.0,
            last_switch_count: task.0.switch_count,
            last_switch_time: Instant::now(),

            // when the kernel has detected a hung task, task.wait_ns will
            // be whatever duration the kernel detected.
            wait_time: task.0.wait_ns as f64 / NSEC_PER_SEC as f64,
            dead: false,
        }
    }
    // when we're hashing the stack traces, we want to be able to pull out
    // the last 10 or so, otherwise we can end up with a lot of noisey but
    // similar traces.
    //
    pub fn copy_kstack(&self, count: usize) -> Vec<u64> {
        let to_copy = std::cmp::min(count, self.ts.kstack_len as usize);
        self.ts.kstack[..to_copy].to_vec()
    }

    // the kernel gives us task state as an integer.  Make it a friendly
    // letter
    pub fn state(&self) -> &str {
        let state = self.ts.state as u64;
        if (state & TASK_NOLOAD) != 0 {
            "I"
        } else if (state & TASK_INTERRUPTIBLE) != 0 {
            "S"
        } else if (state & TASK_UNINTERRUPTIBLE) != 0 {
            "D"
        } else if state == TASK_RUNNING {
            "R"
        } else {
            "?"
        }
    }
    // turn our raw task.comm buffer into a string.
    pub fn comm(&self) -> String {
        let c_str = CStr::from_bytes_until_nul(self.ts.comm.as_slice()).unwrap_or(c"<invalid>");
        c_str.to_string_lossy().into_owned()
    }

    // we store the tasks in a hashmap based on (pid, task_ptr), and run
    // the bpf iterator multiple times.  This allows us to update the
    // stored values based on new data from the kernel
    //
    pub fn update(&mut self, new_task_stack: &task_stack) {
        self.ts.clone_from(new_task_stack);
        let mut kwait = self.ts.wait_ns as f64 / NSEC_PER_SEC as f64;

        // update the count of context switches, store a new timestamp
        if self.last_switch_count != self.ts.switch_count {
            self.last_switch_time = Instant::now();
            self.last_switch_count = self.ts.switch_count;
        } else {
            let twait = self.last_switch_time.elapsed().as_secs_f64();
            if twait > kwait {
                // pick whatever wait time is longer, the kernel's or ours
                kwait = twait;
            }
        }
        self.wait_time = kwait;
    }
}
