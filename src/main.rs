use anyhow::Result;
use blazesym::symbolize;
use blazesym::symbolize::source::Kernel;
use blazesym::symbolize::source::Process;
use blazesym::symbolize::source::Source;
use blazesym::Pid;
use chrono::Local;
use clap::Parser;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::Link;
use libbpf_rs::MapCore;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::LinkedList;
use std::io;
use std::io::Read;
use std::mem::MaybeUninit;
use std::time::Instant;

use std::ffi::CStr;
use std::fs;
use std::io::BufRead;

const RWALKER_ITER_MODE_DSTATE: i32 = 0;
const RWALKER_ITER_MODE_RUNNING: i32 = 1;
const RWALKER_ITER_MODE_ALL: i32 = 2;

//
// stack frame address length
const ADDR_WIDTH: usize = 16;

mod skel;
use skel::rwalker::types::task_stack;

pub mod task;
use task::Task;

mod cpumask;
mod dwarf_unwind;
mod profile;
mod syscall;

use cpumask::parse_cpumask;

// Resolves BPF JIT addresses using /proc/kallsyms.  blazesym uses vmlinux
// for kernel symbols and falls back to kallsyms, but BPF JIT addresses
// land past the last vmlinux symbol (__init_scratch_end) so vmlinux
// "wins" with a bogus match.  We parse the BPF JIT entries from kallsyms
// and do our own lookup for addresses in that range.
struct BpfKsymResolver {
    // sorted by address
    syms: Vec<(u64, String)>,
}

impl BpfKsymResolver {
    fn load() -> Self {
        let mut syms = Vec::new();
        if let Ok(file) = fs::File::open("/proc/kallsyms") {
            for line in io::BufReader::new(file).lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                // Format: "addr type name [module]"
                // BPF JIT entries look like:
                //   ffffffffa009c14c t bpf_prog_50ed5e65e35389a3_tw_chain_fn_0 [bpf]
                if !line.contains("\t[bpf]") && !line.contains(" [bpf]") {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let addr_str = match parts.next() {
                    Some(s) => s,
                    None => continue,
                };
                let _typ = parts.next(); // skip type
                let name = match parts.next() {
                    Some(s) => s,
                    None => continue,
                };
                if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                    if addr > 0 {
                        syms.push((addr, name.to_string()));
                    }
                }
            }
        }
        syms.sort_by_key(|&(addr, _)| addr);
        BpfKsymResolver { syms }
    }

    // Look up an address.  Returns (name, offset) if the address falls
    // within the BPF JIT range.
    fn resolve(&self, addr: u64) -> Option<(&str, usize)> {
        if self.syms.is_empty() {
            return None;
        }
        // Binary search for the highest symbol <= addr
        let idx = match self.syms.binary_search_by_key(&addr, |&(a, _)| a) {
            Ok(i) => i,
            Err(0) => return None, // addr before first BPF symbol
            Err(i) => i - 1,
        };
        let (sym_addr, ref name) = self.syms[idx];
        let offset = (addr - sym_addr) as usize;
        // Sanity: BPF programs are small, reject if offset is huge
        if offset > 1024 * 1024 {
            return None;
        }
        Some((name, offset))
    }
}

// we maintain a map of the stack traces and which tasks
// are stuck in the same call stack.  This collects the hists
// and the list of tasks.
struct TaskCounter<'a> {
    hits: u64,
    tasks: LinkedList<&'a Task>,
}

impl<'a> TaskCounter<'a> {
    fn new() -> TaskCounter<'a> {
        TaskCounter {
            hits: 0,
            tasks: LinkedList::new(),
        }
    }
    fn add(&mut self, task: &'a Task) {
        self.hits += 1;
        self.tasks.push_back(task);
    }
}

// helper to decode a single line in the stack trace.
// verbase means to also print out the raw hex address
fn print_frame(
    name: &str,
    addr_info: Option<(blazesym::Addr, blazesym::Addr, usize)>,
    code_info: Option<&symbolize::CodeInfo<'_>>,
    verbose: bool,
) {
    let code_info = code_info.map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        // If we have various address information bits we have a new symbol.
        if verbose {
            println!(
                "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
                code_info = code_info.as_deref().unwrap_or(""),
                width = ADDR_WIDTH
            )
        } else {
            let code_str = if code_info.is_some() {
                format!("@{}", code_info.as_deref().expect("value"))
            } else {
                "".to_string()
            };

            println!("{:width$} {name} {code_str}", " ", width = ADDR_WIDTH);
        }
    } else {
        println!(
            "{:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
        )
    }
}

fn print_one_stack(
    stack: &[u64],
    src: &Source<'_>,
    symbolizer: &symbolize::Symbolizer,
    verbose: bool,
) {
    if stack.is_empty() {
        return;
    }

    let syms = match symbolizer.symbolize(src, symbolize::Input::AbsAddr(stack)) {
        Ok(syms) => syms,
        Err(err) => {
            eprintln!("  failed to symbolize addresses: {err:#}");
            return;
        }
    };

    for (input_addr, sym) in stack.iter().copied().zip(syms) {
        match sym {
            symbolize::Symbolized::Sym(symbolize::Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                print_frame(
                    &name,
                    Some((input_addr, addr, offset)),
                    code_info.as_deref(),
                    verbose,
                );
                for frame in inlined.iter() {
                    print_frame(&frame.name, None, frame.code_info.as_ref(), verbose);
                }
            }
            symbolize::Symbolized::Unknown(_) => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }
}

// print the kernel traces for a task
// task: the task to print out
// count: max number of frames to print out
// symbolizer: our symbolizer, which caches the dwarf resolution
// options: the command line options
fn print_stack_trace(
    ts: &task_stack,
    count: Option<usize>,
    src: &Source<'_>,
    symbolizer: &symbolize::Symbolizer,
    verbose: bool,
) {
    let frames = if let Some(min_count) = count {
        std::cmp::min(ts.kstack_len as usize, min_count)
    } else {
        ts.kstack_len as usize
    };

    print_one_stack(&ts.kstack[..frames], src, symbolizer, verbose);
}

// before iterating all the tasks, we mark all the tasks from the
// previous run as dead.  This way we can drop tasks that have
// exited or just don't show up as D state anymore
fn mark_tasks_dead(task_pid_map: &mut HashMap<(i32, u64), Task>) {
    for (_, task) in task_pid_map.iter_mut() {
        task.dead = true;
    }
}

// processing all the results of the iterator, drop any tasks we didn't
// see.
fn drop_dead_tasks(task_pid_map: &mut HashMap<(i32, u64), Task>) {
    task_pid_map.retain(|_, task| !task.dead);
}

fn run_kernel_iter(
    link: &Link,
    task_pid_map: &mut HashMap<(i32, u64), Task>,
    waiting: i32,
) -> Vec<Task> {
    let mut iter = libbpf_rs::Iter::new(link).expect("Failed to create iterator");
    let mut buffer: [u8; std::mem::size_of::<task_stack>()] =
        [0u8; std::mem::size_of::<task_stack>()];
    let mut task_list = Vec::<Task>::new();

    loop {
        match iter.read_exact(&mut buffer) {
            Ok(_) => {
                let mut task: Task = Task::new(&buffer);

                let pid_map = task_pid_map.get_mut(&(task.ts.pid, task.ts.task_ptr));

                if let Some(found) = pid_map {
                    found.dead = false;
                    found.update(&task.ts);
                    task.clone_from(found);
                } else {
                    task_pid_map.insert((task.ts.pid, task.ts.task_ptr), task);
                }
                if task.wait_time >= waiting as f64 {
                    task_list.push(task);
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("iterator read error: {e}");
                }
                break;
            }
        }
    }
    task_list
}

fn walk_tasks(
    link: &Link,
    task_pid_map: &mut HashMap<(i32, u64), Task>,
    symbolizer: &symbolize::Symbolizer,
    options: &Options,
) -> bool {
    mark_tasks_dead(task_pid_map);

    let comm_re = if !options.command.is_empty() {
        Some(Regex::new(&options.command).unwrap())
    } else {
        None
    };

    let mut task_list = run_kernel_iter(link, task_pid_map, options.waiting);

    drop_dead_tasks(task_pid_map);

    if task_list.is_empty() {
        if !options.stuck && options.waiting > 0 {
            println!("no tasks waited for at least {} seconds", options.waiting);
        }
        return false;
    }

    let kernel = Kernel {
        debug_syms: !options.quick,
        ..Default::default()
    };
    let src = Source::from(kernel);

    let mut task_stack_map: HashMap<Vec<u64>, TaskCounter<'_>> = HashMap::new();

    // sort by wait time, with the longest waiters at the bottom of the output
    task_list.sort_by(|a, b| a.wait_time.partial_cmp(&b.wait_time).unwrap());

    for task in task_list.iter_mut() {
        let comm = task.comm();
        if let Some(ref re) = comm_re {
            if !re.is_match(&comm) {
                continue;
            }
        }
        println!(
            "comm {} pid {} state {} wait {:.2} queue CPU {}",
            comm,
            &task.ts.pid,
            task.state(),
            task.wait_time,
            task.ts.cpu,
        );

        print_stack_trace(&task.ts, None, &src, symbolizer, options.verbose);

        let stack = task.copy_kstack(6);
        let val = task_stack_map.entry(stack).or_insert(TaskCounter::new());
        val.add(task);
    }

    let mut task_counters: Vec<&TaskCounter<'_>> = task_stack_map.values().collect();

    // sort so the most common stacks are at the top
    task_counters.sort_by(|a, b| b.hits.cmp(&a.hits));

    for tc in task_counters {
        let mut comm_set = HashSet::new();
        let mut state_set = HashSet::new();
        for t in tc.tasks.iter() {
            comm_set.insert(t.comm());
            state_set.insert(t.state());
        }
        let comms = comm_set
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let states = state_set
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        let task = tc.tasks.front().expect("failure to get task");

        println!("{} hits state {} comms {}", tc.hits, states, comms);
        print_stack_trace(&task.ts, Some(6), &src, symbolizer, options.verbose);
    }

    true
}

fn __comm_to_str(comm: &[u8; crate::skel::TASK_COMM_LEN]) -> String {
    let c_str = CStr::from_bytes_until_nul(comm).unwrap_or(c"<invalid>");
    c_str.to_string_lossy().into_owned()
}

// Resolved frame: function name + offset within the function.
// Also used as the leaf symbol type in print_perf_stacks (formerly LeafSym).
#[derive(Clone)]
struct ResolvedFrame {
    name: String,
    offset: usize,
    line_info: String, // pre-formatted "file.c:123" or ""
}

fn resolve_sym(sym: symbolize::Symbolized<'_>) -> ResolvedFrame {
    match sym {
        symbolize::Symbolized::Sym(s) => {
            let line_info = s
                .code_info
                .as_ref()
                .map(|ci| {
                    let path = ci.to_path();
                    let file = path
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_default();
                    match ci.line {
                        Some(line) => format!("{file}:{line}"),
                        None => file,
                    }
                })
                .unwrap_or_default();
            ResolvedFrame {
                name: s.name.to_string(),
                offset: s.offset,
                line_info,
            }
        }
        symbolize::Symbolized::Unknown(_) => ResolvedFrame {
            name: "<no-symbol>".to_string(),
            offset: 0,
            line_info: String::new(),
        },
    }
}

// Call chain tree node for perf-report-style grouping.
// Each node represents a function in the call chain, with children
// representing callees.  The tree is built root-first (outermost caller
// at the root, leaf/self function at the leaves).
// Per-offset tracking: cumulative hits and the associated source location.
struct OffsetInfo {
    hits: u64,
    line_info: String,
}

struct CallTreeNode {
    hits: u64,
    children: HashMap<String, CallTreeNode>,
    // Track offset → (cumulative hits, line info) for display
    offsets: HashMap<usize, OffsetInfo>,
}

impl CallTreeNode {
    fn new() -> Self {
        CallTreeNode {
            hits: 0,
            children: HashMap::new(),
            offsets: HashMap::new(),
        }
    }

    // Insert a call chain (root→...→leaf) into the tree, adding hits
    // at every node along the path.
    fn insert(&mut self, chain: &[ResolvedFrame], hits: u64) {
        self.hits += hits;
        if !chain.is_empty() {
            let child = self
                .children
                .entry(chain[0].name.clone())
                .or_insert_with(CallTreeNode::new);
            // Record this offset and line info on the child node
            let info = child.offsets.entry(chain[0].offset).or_insert(OffsetInfo {
                hits: 0,
                line_info: chain[0].line_info.clone(),
            });
            info.hits += hits;
            child.insert(&chain[1..], hits);
        }
    }

    // Return the (offset, line_info) with the most hits at this node.
    fn best_offset_info(&self) -> Option<(usize, &str)> {
        self.offsets
            .iter()
            .max_by_key(|(_, info)| info.hits)
            .map(|(&offset, info)| (offset, info.line_info.as_str()))
    }
}

// Print a call chain tree in perf-report style.
// Linear chains (single child) print inline.
// Branch points show |--pct%--function for each branch.
// Format a tree node's name with its heaviest offset.
fn format_node_name(name: &str, node: &CallTreeNode) -> String {
    match node.best_offset_info() {
        Some((offset, line_info)) if offset > 0 => {
            if line_info.is_empty() {
                format!("{name}+{offset:#x}")
            } else {
                format!("{name}+{offset:#x} {line_info}")
            }
        }
        _ => name.to_string(),
    }
}

fn print_call_chain(node: &CallTreeNode, total_events: u64, prefix: &str, min_pct: f64) {
    // Always include the heaviest child so there's at least one
    // complete path through the tree, even if below the threshold.
    let mut children: Vec<_> = node.children.iter().collect();
    children.sort_by(|a, b| b.1.hits.cmp(&a.1.hits));
    let heaviest_hits = children.first().map(|(_, c)| c.hits).unwrap_or(0);
    children.retain(|(_, child)| {
        child.hits == heaviest_hits || (child.hits as f64 / total_events as f64) * 100.0 >= min_pct
    });

    match children.len() {
        0 => {}
        1 => {
            // Single child - linear chain, no branching
            let (name, child) = children[0];
            let display = format_node_name(name, child);
            println!("{prefix}{display}");
            print_call_chain(child, total_events, prefix, min_pct);
        }
        _ => {
            // Multiple children - branch point
            for (i, (name, child)) in children.iter().enumerate() {
                let is_last = i == children.len() - 1;
                let pct = (child.hits as f64 / total_events as f64) * 100.0;
                let display = format_node_name(name, child);
                let marker = format!("--{pct:.2}%--");
                if is_last {
                    println!("{prefix} {marker}{display}");
                    let pad = " ".repeat(marker.len() + 1);
                    print_call_chain(child, total_events, &format!("{prefix}{pad}"), min_pct);
                } else {
                    println!("{prefix}|{marker}{display}");
                    let pad = " ".repeat(marker.len());
                    print_call_chain(child, total_events, &format!("{prefix}|{pad}"), min_pct);
                }
            }
        }
    }
}

// Samples grouped by leaf (self) function, with a call chain tree
// showing all the paths that led to that function.
struct LeafGroup {
    hits: u64,
    total_ns: u64,
    best_offset: usize,
    best_offset_hits: u64,
    best_line_info: String,
    comms: HashSet<[u8; crate::skel::TASK_COMM_LEN]>,
    tree: CallTreeNode,
}

// Print profiling results in perf-report style:
// 1. Symbolize only leaf addresses (cheap, kernel source) to group by function
// 2. Filter groups below 0.25% threshold
// 3. Symbolize full stacks only for surviving groups
// 4. Print with branching where callers diverge, ordered by overhead
fn print_perf_stacks(
    profiler: &mut profile::Profiler,
    symbolizer: &symbolize::Symbolizer,
    options: &Options,
    bpf_resolver: &BpfKsymResolver,
) {
    let kernel = Kernel {
        debug_syms: !options.quick,
        ..Default::default()
    };
    let kernel_src = Source::from(kernel);
    let total_events = *profiler.total_events.borrow();
    let total_ns = *profiler.total_ns.borrow();
    let offcpu = options.offcpu > 0;

    if total_events == 0 {
        return;
    }

    // In offcpu mode, weight by total blocked time; in on-CPU mode, by sample count
    let total_weight = if offcpu { total_ns } else { total_events };
    let map = profiler.perf_stack_map.borrow();
    let hit_threshold = 1u64;

    // Phase 1: batch-symbolize all unique leaf addresses.
    // Kernel addresses (above 0xffff...) use the kernel source.
    // User addresses use per-pid Process sources.
    let is_kernel_addr = |a: u64| a >= 0xffff_0000_0000_0000;

    let mut kernel_leaf_addrs: Vec<u64> = map
        .keys()
        .map(|f| f.leaf_addr())
        .filter(|a| *a != 0 && is_kernel_addr(*a))
        .collect();
    kernel_leaf_addrs.sort_unstable();
    kernel_leaf_addrs.dedup();

    let leaf_syms = symbolizer
        .symbolize(&kernel_src, symbolize::Input::AbsAddr(&kernel_leaf_addrs))
        .unwrap_or_default();

    let mut leaf_sym_map: HashMap<u64, ResolvedFrame> = HashMap::new();
    for (addr, sym) in kernel_leaf_addrs.iter().copied().zip(leaf_syms) {
        // Check BPF JIT resolver first
        if let Some((bpf_name, bpf_offset)) = bpf_resolver.resolve(addr) {
            leaf_sym_map.insert(
                addr,
                ResolvedFrame {
                    name: bpf_name.to_string(),
                    offset: bpf_offset,
                    line_info: String::new(),
                },
            );
            continue;
        }
        leaf_sym_map.insert(addr, resolve_sym(sym));
    }

    // Process sources are built incrementally — phase 1b adds pids for
    // user-leaf samples, phase 3 adds remaining pids for surviving groups.
    let mut process_sources: HashMap<i32, Source<'_>> = HashMap::new();

    // Phase 1b: symbolize user-leaf addresses (samples that fired in
    // user mode with no kernel stack).  These need per-pid Process sources.
    if options.user {
        // Collect (pid, addr) pairs for user-leaf samples
        let mut user_leaf_by_pid: HashMap<i32, Vec<u64>> = HashMap::new();
        for frame in map.keys() {
            let leaf = frame.leaf_addr();
            if leaf != 0 && !is_kernel_addr(leaf) && frame.pid > 0 {
                user_leaf_by_pid.entry(frame.pid).or_default().push(leaf);
            }
        }
        for (pid, addrs) in user_leaf_by_pid.iter_mut() {
            addrs.sort_unstable();
            addrs.dedup();
            let proc_src = process_sources.entry(*pid).or_insert_with(|| {
                let mut proc = Process::new(Pid::from(*pid as u32));
                proc.debug_syms = !options.quick;
                Source::from(proc)
            });
            let syms = symbolizer
                .symbolize(proc_src, symbolize::Input::AbsAddr(addrs))
                .unwrap_or_default();
            for (addr, sym) in addrs.iter().copied().zip(syms) {
                leaf_sym_map.insert(addr, resolve_sym(sym));
            }
        }
    }

    // BPF overhead filter — used in phase 2 leaf lookup and phase 4c display
    let is_bpf_overhead = |name: &str| -> bool {
        name.starts_with("__bpf_get_stack")
            || name.starts_with("bpf_get_stack")
            || name.starts_with("__bpf_get_task_stack")
            || name.starts_with("bpf_prog_")
            || name.starts_with("bpf_trampoline_")
            || name.starts_with("bpf_trace_run")
    };

    // Helper: find the real leaf addr by skipping BPF overhead frames
    let find_real_leaf = |frame: &profile::ProfileFrame| -> u64 {
        for addr in frame.kframe.iter() {
            if let Some(sym) = leaf_sym_map.get(addr) {
                if !is_bpf_overhead(&sym.name) {
                    return *addr;
                }
            } else {
                // Unknown address — not BPF overhead, use it
                return *addr;
            }
        }
        // All kernel frames are BPF overhead — fall back to user leaf
        frame.uframe.first().copied().unwrap_or(0)
    };

    // Phase 2: aggregate hits by leaf function NAME.  Track the hottest
    // offset within each function.  Filter by -c comm regex if set.
    let comm_re = if !options.command.is_empty() {
        Some(Regex::new(&options.command).unwrap())
    } else {
        None
    };

    let mut func_hits: HashMap<String, (u64, usize, u64, String)> = HashMap::new();
    for (frame, counter) in map.iter() {
        // Skip entries that don't match the -c filter
        if let Some(ref re) = comm_re {
            if !counter.comms.iter().any(|c| re.is_match(&__comm_to_str(c))) {
                continue;
            }
        }

        let leaf_addr = find_real_leaf(frame);
        if leaf_addr == 0 {
            continue;
        }
        let leaf = leaf_sym_map.get(&leaf_addr);
        let name = leaf.map(|l| l.name.as_str()).unwrap_or("<no-symbol>");
        let offset = leaf.map(|l| l.offset).unwrap_or(0);
        let line_info = leaf.map(|l| l.line_info.as_str()).unwrap_or("");

        let weight = if offcpu {
            counter.total_ns
        } else {
            counter.hits
        };
        let entry = func_hits
            .entry(name.to_string())
            .or_insert((0, 0, 0, String::new()));
        entry.0 += weight;
        if weight > entry.2 {
            entry.1 = offset;
            entry.2 = counter.hits;
            entry.3 = line_info.to_string();
        }
    }

    // Phase 3: build Process sources only for pids in surviving groups
    let surviving_funcs: HashSet<&str> = func_hits
        .iter()
        .filter(|(_, (hits, _, _, _))| *hits >= hit_threshold)
        .map(|(name, _)| name.as_str())
        .collect();

    if options.user {
        for (frame, _) in map.iter() {
            let leaf_addr = find_real_leaf(frame);
            let name = leaf_sym_map
                .get(&leaf_addr)
                .map(|l| l.name.as_str())
                .unwrap_or("<no-symbol>");
            if surviving_funcs.contains(name) && !frame.uframe.is_empty() && frame.pid > 0 {
                process_sources.entry(frame.pid).or_insert_with(|| {
                    let mut proc = Process::new(Pid::from(frame.pid as u32));
                    proc.debug_syms = !options.quick;
                    Source::from(proc)
                });
            }
        }
    }

    // Phase 4a: accumulate hits, comms, and best offset per leaf group
    // using the already-resolved leaf symbols from phase 1 (no new
    // symbolization).
    let mut leaf_groups: HashMap<String, LeafGroup> = HashMap::new();
    for (frame, counter) in map.iter() {
        if let Some(ref re) = comm_re {
            if !counter.comms.iter().any(|c| re.is_match(&__comm_to_str(c))) {
                continue;
            }
        }
        let leaf_addr = find_real_leaf(frame);
        if leaf_addr == 0 {
            continue;
        }
        let leaf = leaf_sym_map.get(&leaf_addr);
        let name = leaf.map(|l| l.name.as_str()).unwrap_or("<no-symbol>");
        if !surviving_funcs.contains(name) {
            continue;
        }
        let offset = leaf.map(|l| l.offset).unwrap_or(0);
        let line_info = leaf.map(|l| l.line_info.as_str()).unwrap_or("");

        let weight = if offcpu {
            counter.total_ns
        } else {
            counter.hits
        };
        let group = leaf_groups.entry(name.to_string()).or_insert(LeafGroup {
            hits: 0,
            total_ns: 0,
            best_offset: 0,
            best_offset_hits: 0,
            best_line_info: String::new(),
            comms: HashSet::new(),
            tree: CallTreeNode::new(),
        });
        group.hits += counter.hits;
        group.total_ns += counter.total_ns;
        group.comms.extend(&counter.comms);
        if weight > group.best_offset_hits {
            group.best_offset = offset;
            group.best_offset_hits = weight;
            group.best_line_info = line_info.to_string();
        }
    }

    // Phase 4b: collect ALL unique addresses from surviving stacks,
    // then batch-symbolize them in one call per source.  This triggers
    // blazesym's symtab sort once instead of incrementally per-stack.
    let mut all_kernel_addrs: Vec<u64> = Vec::new();
    let mut all_user_addrs: HashMap<i32, Vec<u64>> = HashMap::new();

    for (frame, counter) in map.iter() {
        if let Some(ref re) = comm_re {
            if !counter.comms.iter().any(|c| re.is_match(&__comm_to_str(c))) {
                continue;
            }
        }
        let leaf_addr = find_real_leaf(frame);
        let name = leaf_sym_map
            .get(&leaf_addr)
            .map(|l| l.name.as_str())
            .unwrap_or("<no-symbol>");
        if !surviving_funcs.contains(name) {
            continue;
        }
        all_kernel_addrs.extend_from_slice(&frame.kframe);
        if options.user && !frame.uframe.is_empty() && frame.pid > 0 {
            all_user_addrs
                .entry(frame.pid)
                .or_default()
                .extend_from_slice(&frame.uframe);
        }
    }

    // Deduplicate and batch-resolve all kernel addresses
    all_kernel_addrs.sort_unstable();
    all_kernel_addrs.dedup();
    let mut kernel_cache: HashMap<u64, ResolvedFrame> = HashMap::new();
    // Seed cache from phase 1 leaf results
    for (addr, ls) in &leaf_sym_map {
        kernel_cache.insert(
            *addr,
            ResolvedFrame {
                name: ls.name.clone(),
                offset: ls.offset,
                line_info: ls.line_info.clone(),
            },
        );
    }
    // Resolve remaining kernel addresses not already in cache
    let kernel_misses: Vec<u64> = all_kernel_addrs
        .iter()
        .copied()
        .filter(|a| !kernel_cache.contains_key(a))
        .collect();
    if !kernel_misses.is_empty() {
        let syms = symbolizer
            .symbolize(&kernel_src, symbolize::Input::AbsAddr(&kernel_misses))
            .unwrap_or_default();
        for (addr, sym) in kernel_misses.iter().copied().zip(syms) {
            if let Some((bpf_name, bpf_offset)) = bpf_resolver.resolve(addr) {
                kernel_cache.insert(
                    addr,
                    ResolvedFrame {
                        name: bpf_name.to_string(),
                        offset: bpf_offset,
                        line_info: String::new(),
                    },
                );
                continue;
            }
            kernel_cache.insert(addr, resolve_sym(sym));
        }
    }

    // Deduplicate and batch-resolve all user addresses per pid
    let mut user_caches: HashMap<i32, HashMap<u64, ResolvedFrame>> = HashMap::new();
    for (pid, addrs) in all_user_addrs.iter_mut() {
        addrs.sort_unstable();
        addrs.dedup();
        if let Some(proc_src) = process_sources.get(pid) {
            let ucache = user_caches.entry(*pid).or_default();
            let syms = symbolizer
                .symbolize(proc_src, symbolize::Input::AbsAddr(addrs))
                .unwrap_or_default();
            for (addr, sym) in addrs.iter().copied().zip(syms) {
                ucache.insert(addr, resolve_sym(sym));
            }
        }
    }

    // Phase 4c: build the call chain trees from the fully-populated caches.
    // No more blazesym calls — pure cache lookups.
    for (frame, counter) in map.iter() {
        if let Some(ref re) = comm_re {
            if !counter.comms.iter().any(|c| re.is_match(&__comm_to_str(c))) {
                continue;
            }
        }
        let leaf_addr = find_real_leaf(frame);
        let name = leaf_sym_map
            .get(&leaf_addr)
            .map(|l| l.name.as_str())
            .unwrap_or("<no-symbol>");
        if !surviving_funcs.contains(name) {
            continue;
        }

        // Resolve kernel frames from cache, stripping BPF overhead
        // from the leaf end
        let kframes: Vec<ResolvedFrame> = frame
            .kframe
            .iter()
            .map(|a| {
                kernel_cache.get(a).cloned().unwrap_or(ResolvedFrame {
                    name: format!("{a:#x}"),
                    offset: 0,
                    line_info: String::new(),
                })
            })
            .skip_while(|f| is_bpf_overhead(&f.name))
            .collect();

        // Resolve user frames from cache
        let mut uframes: Vec<ResolvedFrame> =
            if options.user && !frame.uframe.is_empty() && frame.pid > 0 {
                if let Some(ucache) = user_caches.get(&frame.pid) {
                    frame
                        .uframe
                        .iter()
                        .map(|a| {
                            ucache.get(a).cloned().unwrap_or(ResolvedFrame {
                                name: "<no-symbol>".to_string(),
                                offset: 0,
                                line_info: String::new(),
                            })
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

        // Trim <no-symbol> runs from both ends of user stacks
        if let Some(first_good) = uframes.iter().position(|f| f.name != "<no-symbol>") {
            uframes.drain(..first_good);
        }
        while uframes.last().is_some_and(|f| f.name == "<no-symbol>") {
            uframes.pop();
        }

        // Combined stack (leaf-first): kernel frames then user frames.
        let mut frames: Vec<ResolvedFrame> = Vec::with_capacity(kframes.len() + uframes.len());
        frames.extend(kframes);
        frames.extend(uframes);

        if frames.is_empty() {
            continue;
        }

        let group = leaf_groups.get_mut(name).unwrap();

        // Reverse: build tree from root (outermost caller) → leaf
        let weight = if offcpu {
            counter.total_ns
        } else {
            counter.hits
        };
        let chain: Vec<ResolvedFrame> = frames.into_iter().rev().collect();
        group.tree.insert(&chain, weight);
    }

    // Sort by overhead, heaviest first
    let mut sorted: Vec<_> = leaf_groups.into_iter().collect();
    sorted.sort_by(|a, b| {
        let aw = if offcpu { b.1.total_ns } else { b.1.hits };
        let bw = if offcpu { a.1.total_ns } else { a.1.hits };
        aw.cmp(&bw)
    });

    let adjusted_total = total_weight;

    let mut displayed = 0;
    for (leaf_name, group) in sorted.iter() {
        if is_bpf_overhead(leaf_name) {
            continue;
        }
        if displayed >= 20 {
            break;
        }
        let group_weight = if offcpu { group.total_ns } else { group.hits };
        let pct = (group_weight as f64 / adjusted_total as f64) * 100.0;
        if pct < options.output_filter {
            continue;
        }
        displayed += 1;

        let mut comms: String = group
            .comms
            .iter()
            .take(4)
            .map(__comm_to_str)
            .collect::<Vec<String>>()
            .join(", ");

        if group.comms.len() > 4 {
            comms.push_str(", ...");
        }

        // Show the hottest offset in the leaf function
        let leaf_display = if group.best_offset > 0 {
            if group.best_line_info.is_empty() {
                format!("{leaf_name}+{:#x}", group.best_offset)
            } else {
                format!(
                    "{leaf_name}+{:#x} {}",
                    group.best_offset, group.best_line_info
                )
            }
        } else {
            leaf_name.clone()
        };

        println!();
        if offcpu {
            let ms = group.total_ns as f64 / 1_000_000.0;
            println!(
                ">>> {:.2}% ({:.1}ms)  {}  Comms: {}",
                pct, ms, leaf_display, comms
            );
        } else {
            println!(">>> {:.2}%  {}  Comms: {}", pct, leaf_display, comms);
        }
        println!("            |");
        print_call_chain(
            &group.tree,
            adjusted_total,
            "            ",
            options.output_filter,
        );
    }
}

#[derive(clap::Parser, Debug, Clone)]
#[clap(name = "walker", about = "Aggregate stacks of tasks")]
pub struct Options {
    /// prints the function address as well as name
    #[clap(long, short, action = clap::ArgAction::SetTrue) ]
    verbose: bool,
    /// Dump all stacks
    #[clap(long, short, action = clap::ArgAction::SetTrue) ]
    all: bool,
    /// Filter on command name, accepts a regex
    #[clap(long, short = 'c', default_value = "")]
    command: String,
    /// don't use the more expensive dwarf symbolizer
    #[clap(long, short, action = clap::ArgAction::SetTrue) ]
    quick: bool,
    /// only print running tasks
    #[clap(long, short, action = clap::ArgAction::SetTrue) ]
    running: bool,
    /// wait a few seconds looking for stuck tasks
    #[clap(long, short, action = clap::ArgAction::SetTrue) ]
    stuck: bool,
    /// only print if a task is waiting longer than N seconds
    #[clap(long, short = 'w', value_parser, default_value_t = 0)]
    waiting: i32,
    /// sleep this many seconds and then re-read the task stacks
    #[clap(long, short = 'i', value_parser, default_value_t = 0)]
    interval: i32,
    /// stop after this many loops in interval mode
    #[clap(long, short = 'C', value_parser, default_value_t = 0)]
    count: i32,
    /// profile CPU usage for this many seconds
    #[clap(long, short = 'p', value_parser, default_value_t = 0)]
    profile: i32,
    #[clap(long, short = 'P', value_parser)]
    cpus: Option<String>,
    /// sampling frequency in Hz (samples per second per CPU)
    #[clap(long, short = 'f', value_parser, default_value_t = 4000)]
    freq: u64,
    /// force software CPU clock events instead of hardware PMU
    #[clap(long, action = clap::ArgAction::SetTrue)]
    sw_perf: bool,
    /// include user-space stacks in profiling (requires frame pointers in target binaries)
    #[clap(long, short = 'u', action = clap::ArgAction::SetTrue)]
    user: bool,
    /// profile off-CPU (blocked) time for this many seconds
    #[clap(long, value_parser, default_value_t = 0)]
    offcpu: i32,
    /// trace a kernel tracepoint (format: name:seconds, e.g. submit_bio:5)
    #[clap(long, value_parser)]
    trace: Option<String>,
    /// trace a kernel function via fentry (format: name:seconds, e.g. ksys_write:5)
    #[clap(long, value_parser)]
    kfunc: Option<String>,
    /// use DWARF unwinding for user stacks (works without frame pointers)
    #[clap(long, action = clap::ArgAction::SetTrue)]
    dwarf: bool,
    /// only show leaf functions above this percentage
    #[clap(long, value_parser, default_value_t = 1.0)]
    output_filter: f64,
    /// dwarf ringbuf size in MB (increase for high-rate tracepoints)
    #[clap(long, value_parser, default_value_t = 192)]
    dwarf_ringbuf_size: u32,
    /// ringbuf size in MB for frame-pointer samples
    #[clap(long, value_parser, default_value_t = 64)]
    ringbuf_size: u32,
}

fn main() -> Result<()> {
    let mut options = Options::parse();

    // Open skeleton
    let skel_builder = skel::rwalker::RwalkerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object).unwrap();

    // Declare the symbolizer out here so it caches the resulting dwarf
    let symbolizer = symbolize::Symbolizer::new();

    // Load BPF JIT symbols from /proc/kallsyms for resolving BPF program addresses
    let bpf_resolver = BpfKsymResolver::load();

    // Parse --trace name:seconds and --kfunc name:seconds
    let mut trace_name: Option<String> = None;
    let mut kfunc_name: Option<String> = None;
    let mut trace_duration: i32 = 0;
    if let Some(ref trace_arg) = options.trace {
        let (name, secs) = trace_arg
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("--trace format: name:seconds (e.g. sched_switch:5)"))?;
        trace_duration = secs
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid duration: {secs}"))?;
        trace_name = Some(name.to_string());
    }
    if let Some(ref kfunc_arg) = options.kfunc {
        let (name, secs) = kfunc_arg
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("--kfunc format: name:seconds (e.g. ksys_write:5)"))?;
        trace_duration = secs
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid duration: {secs}"))?;
        kfunc_name = Some(name.to_string());
    }

    // Control which BPF programs are loaded — only load what's needed
    let use_trace = trace_name.is_some();
    let use_kfunc = kfunc_name.is_some();
    if !use_trace {
        open_skel.progs.trace_event.set_autoload(false);
    }
    if !use_kfunc {
        open_skel.progs.kfunc_event.set_autoload(false);
    } else {
        open_skel
            .progs
            .kfunc_event
            .set_attach_target(0, kfunc_name.clone())?;
        // Don't auto-attach — we attach manually in Profiler::setup
        open_skel.progs.kfunc_event.set_autoattach(false);
    }
    if options.offcpu == 0 {
        open_skel.progs.offcpu_switch.set_autoload(false);
    }
    if use_trace || use_kfunc || options.offcpu > 0 {
        open_skel.progs.profile.set_autoload(false);
    }

    let rodata = open_skel.maps.rodata_data.as_mut().unwrap();
    if options.all {
        rodata.iter_mode = RWALKER_ITER_MODE_ALL;
    } else if options.running {
        rodata.iter_mode = RWALKER_ITER_MODE_RUNNING;
    } else {
        rodata.iter_mode = RWALKER_ITER_MODE_DSTATE;
    }
    open_skel
        .maps
        .events
        .set_max_entries(options.ringbuf_size * 1024 * 1024)
        .expect("failed to set events ringbuf size");
    if options.dwarf {
        rodata.dwarf_mode = 1;
        open_skel
            .maps
            .dwarf_events
            .set_max_entries(options.dwarf_ringbuf_size * 1024 * 1024)
            .expect("failed to set dwarf_events ringbuf size");
    } else {
        // Minimize DWARF offcpu maps when not in DWARF mode
        open_skel
            .maps
            .offcpu_dwarf_start
            .set_max_entries(1)
            .expect("failed to set offcpu_dwarf_start size");
    }

    //
    // in stuck mode, loop a few times and exit as soon as we find some
    // D state tasks.
    if options.stuck {
        options.interval = 2;
        options.count = 5;
        options.waiting = 1;
    }

    let mut cpus_to_profile: Option<Vec<u32>> = None;
    if options.cpus.is_some() {
        match parse_cpumask(options.cpus.as_ref().unwrap()) {
            Ok(g) => cpus_to_profile = Some(g),
            Err(err) => {
                eprintln!("Invalid cpu string for profiling: {}", err);
                std::process::exit(1);
            }
        }
        println!("Profiling CPUS: {}", options.cpus.as_ref().unwrap());
    }

    // load skeleton into kernel
    let mut skel = open_skel.load().unwrap();
    skel.attach().unwrap();

    // make a mapping of (pid, task_ptr) -> Task so that we can
    // calculate wait times of tasks we collect over time
    let mut task_pid_map: HashMap<(i32, u64), Task> = HashMap::new();

    let mut profiler = None;
    let is_profiling = options.profile > 0 || options.offcpu > 0 || use_trace || use_kfunc;
    if is_profiling {
        profiler = Some(profile::Profiler::new(cpus_to_profile));
        let offcpu = options.offcpu > 0;
        // In dwarf mode, reduce default frequency — each sample is ~18KB
        // vs ~2KB without dwarf.  Only apply if user didn't set -f explicitly.
        let freq = if options.dwarf && options.freq == 4000 {
            eprintln!("dwarf: reducing sampling frequency to 200 Hz (use -f to override)");
            200
        } else {
            options.freq
        };
        profiler.as_mut().unwrap().setup(
            &skel,
            freq,
            options.sw_perf,
            options.user,
            offcpu,
            trace_name.clone(),
            use_kfunc,
            options.dwarf,
        )?;
    }

    let mut loops = 0;
    loop {
        if options.interval > 0 && !options.stuck {
            println!("=== {} ===", Local::now().format("%Y-%m-%d %H:%M:%S"));
        }

        let mut found = false;
        if !is_profiling {
            found = walk_tasks(
                skel.links.get_task_stacks.as_ref().unwrap(),
                &mut task_pid_map,
                &symbolizer,
                &options,
            );
        } else {
            let duration_secs = if trace_duration > 0 {
                // --trace or --kfunc
                trace_duration
            } else if options.offcpu > 0 {
                options.offcpu
            } else {
                options.profile
            };
            let profile_duration = std::time::Duration::from_secs(duration_secs as u64);
            let start = Instant::now();
            loop {
                let elapsed = start.elapsed();
                if elapsed >= profile_duration {
                    profiler.as_mut().unwrap().unwind_dwarf_samples();
                    // Read drop count from BPF per-CPU array
                    let key = 0u32.to_ne_bytes();
                    if let Ok(Some(values)) = skel
                        .maps
                        .drop_count
                        .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
                    {
                        let total_drops: u64 = values
                            .iter()
                            .map(|v| {
                                if v.len() >= 8 {
                                    u64::from_ne_bytes(v[..8].try_into().unwrap_or([0; 8]))
                                } else {
                                    0
                                }
                            })
                            .sum();
                        if total_drops > 0 {
                            let total = *profiler.as_ref().unwrap().total_events.borrow();
                            eprintln!(
                                "warning: {} samples dropped due to ringbuf overflow ({:.1}% loss)",
                                total_drops,
                                total_drops as f64 / (total + total_drops) as f64 * 100.0
                            );
                        }
                    }
                    print_perf_stacks(
                        profiler.as_mut().unwrap(),
                        &symbolizer,
                        &options,
                        &bpf_resolver,
                    );
                    profiler.as_mut().unwrap().reset_frames();
                    break;
                }
                let remaining = profile_duration - elapsed;
                profiler.as_mut().unwrap().poll(remaining);
            }
        }

        loops += 1;

        if (found && options.stuck)
            || options.interval <= 0
            || (options.count > 0 && loops >= options.count)
        {
            break;
        }
        if !is_profiling {
            let sleep_time = options.interval as u64;
            std::thread::sleep(std::time::Duration::from_secs(sleep_time));
        }
    }
    if is_profiling {
        profiler.as_mut().unwrap().close();
    }

    Ok(())
}
