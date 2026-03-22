// this module is just a shell to make it easier to include the generated
// skel.rs file from BPF
//
pub mod rwalker {
    include!(concat!(env!("OUT_DIR"), "/rwalker.skel.rs"));
}

#[allow(unused_imports)]
pub use rwalker::types::task_stack;
#[allow(unused_imports)]
pub use rwalker::*;

pub const BPF_MAX_STACK_DEPTH: usize = 127;
pub const TASK_COMM_LEN: usize = 16;
