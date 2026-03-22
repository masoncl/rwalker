use anyhow::Result;
use blazesym::symbolize;
use blazesym::symbolize::source::Kernel;
use blazesym::symbolize::source::Source;
use chrono::Local;
use clap::Parser;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::Link;
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
struct ResolvedFrame {
    name: String,
    offset: usize,
    line_info: String, // pre-formatted "file.c:123" or ""
}

// Resolve a raw address stack to function names + offsets for grouping.
// Only extracts the primary (non-inlined) symbol per address.
// Uses the BPF ksym resolver for addresses in the BPF JIT region.
fn symbolize_to_frames(
    stack: &[u64],
    src: &Source<'_>,
    symbolizer: &symbolize::Symbolizer,
    bpf_resolver: &BpfKsymResolver,
) -> Vec<ResolvedFrame> {
    if stack.is_empty() {
        return Vec::new();
    }

    let syms = match symbolizer.symbolize(src, symbolize::Input::AbsAddr(stack)) {
        Ok(syms) => syms,
        Err(_) => {
            return stack
                .iter()
                .map(|a| ResolvedFrame {
                    name: format!("{a:#x}"),
                    offset: 0,
                    line_info: String::new(),
                })
                .collect()
        }
    };

    stack
        .iter()
        .copied()
        .zip(syms)
        .map(|(addr, sym)| {
            // Check BPF JIT resolver first for this address
            if let Some((bpf_name, bpf_offset)) = bpf_resolver.resolve(addr) {
                return ResolvedFrame {
                    name: bpf_name.to_string(),
                    offset: bpf_offset,
                    line_info: String::new(),
                };
            }

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
        })
        .collect()
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

fn print_call_chain(node: &CallTreeNode, total_events: u64, prefix: &str) {
    let mut children: Vec<_> = node
        .children
        .iter()
        .filter(|(_, child)| (child.hits as f64 / total_events as f64) * 100.0 >= 0.25)
        .collect();
    children.sort_by(|a, b| b.1.hits.cmp(&a.1.hits));

    match children.len() {
        0 => {}
        1 => {
            // Single child - linear chain, no branching
            let (name, child) = children[0];
            let display = format_node_name(name, child);
            println!("{prefix}{display}");
            print_call_chain(child, total_events, prefix);
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
                    print_call_chain(child, total_events, &format!("{prefix}{pad}"));
                } else {
                    println!("{prefix}|{marker}{display}");
                    let pad = " ".repeat(marker.len());
                    print_call_chain(child, total_events, &format!("{prefix}|{pad}"));
                }
            }
        }
    }
}

// Samples grouped by leaf (self) function, with a call chain tree
// showing all the paths that led to that function.
struct LeafGroup {
    hits: u64,
    comms: HashSet<[u8; crate::skel::TASK_COMM_LEN]>,
    tree: CallTreeNode,
}

// Print profiling results in perf-report style:
// 1. Group all samples by their leaf function (where CPU was executing)
// 2. For each leaf, build a tree of call chains from root to leaf
// 3. Print with branching where callers diverge, ordered by overhead
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
    let src = Source::from(kernel);
    let total_events = *profiler.total_events.borrow();

    if total_events == 0 {
        return;
    }

    // Group by leaf function, building call chain trees
    let mut leaf_groups: HashMap<String, LeafGroup> = HashMap::new();
    let map = profiler.perf_stack_map.borrow();

    for (frame, counter) in map.iter() {
        let frames = symbolize_to_frames(&frame.frame, &src, symbolizer, bpf_resolver);
        if frames.is_empty() {
            continue;
        }

        // frames[0] is the leaf (self) function, frames[last] is the root
        let leaf = frames[0].name.clone();
        let group = leaf_groups.entry(leaf).or_insert(LeafGroup {
            hits: 0,
            comms: HashSet::new(),
            tree: CallTreeNode::new(),
        });
        group.hits += counter.hits;
        group.comms.extend(&counter.comms);

        // Reverse: build tree from root (outermost caller) → leaf
        let chain: Vec<ResolvedFrame> = frames.into_iter().rev().collect();
        group.tree.insert(&chain, counter.hits);
    }

    // Sort by overhead, heaviest first
    let mut sorted: Vec<_> = leaf_groups.into_iter().collect();
    sorted.sort_by(|a, b| b.1.hits.cmp(&a.1.hits));

    for (leaf_name, group) in sorted.iter().take(20) {
        let pct = (group.hits as f64 / total_events as f64) * 100.0;
        if pct < 0.25 {
            continue;
        }

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
        println!();
        println!(">>> {:.2}%  {}  Comms: {}", pct, leaf_name, comms);
        println!("            |");
        print_call_chain(&group.tree, total_events, "            ");
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

    let rodata = open_skel.maps.rodata_data.as_mut().unwrap();
    if options.all {
        rodata.iter_mode = RWALKER_ITER_MODE_ALL;
    } else if options.running {
        rodata.iter_mode = RWALKER_ITER_MODE_RUNNING;
    } else {
        rodata.iter_mode = RWALKER_ITER_MODE_DSTATE;
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
    if options.profile > 0 {
        profiler = Some(profile::Profiler::new(cpus_to_profile));
        profiler.as_mut().unwrap().setup(&skel, options.freq)?;
    }

    let mut loops = 0;
    loop {
        if options.interval > 0 && !options.stuck {
            println!("=== {} ===", Local::now().format("%Y-%m-%d %H:%M:%S"));
        }

        let mut found = false;
        if options.profile == 0 {
            found = walk_tasks(
                skel.links.get_task_stacks.as_ref().unwrap(),
                &mut task_pid_map,
                &symbolizer,
                &options,
            );
        } else {
            let profile_duration = std::time::Duration::from_secs(options.profile as u64);
            let start = Instant::now();
            loop {
                let elapsed = start.elapsed();
                if elapsed >= profile_duration {
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
        if options.profile == 0 {
            let sleep_time = options.interval as u64 - options.profile as u64;
            std::thread::sleep(std::time::Duration::from_secs(sleep_time));
        }
    }
    if options.profile > 0 {
        profiler.as_mut().unwrap().close();
    }

    Ok(())
}
