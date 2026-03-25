use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

use gimli::{
    BaseAddresses, CfaRule, EhFrame, NativeEndian, RegisterRule, UnwindContext, UnwindSection,
};
use memmap2::Mmap;

const MAX_FRAMES: usize = 127;

/// A mapped VMA region from /proc/<pid>/maps
struct VmaEntry {
    start: u64,
    end: u64,
    offset: u64,
    path: PathBuf,
}

/// Cached .eh_frame data for a single ELF binary
struct EhFrameCache {
    mmap: Mmap,
    eh_frame_offset: usize,
    eh_frame_len: usize,
    eh_frame_vaddr: u64,
    text_vaddr: u64,
    /// p_vaddr - p_offset of the lowest PT_LOAD segment.
    /// For PIE binaries, the runtime load address = vma.start - vma.offset + elf_load_bias.
    elf_load_bias: u64,
}

/// Per-pid unwinder with VMA and ELF caches
pub struct DwarfUnwinder {
    vma_cache: HashMap<i32, Vec<VmaEntry>>,
    elf_cache: HashMap<PathBuf, Option<EhFrameCache>>,
}

impl DwarfUnwinder {
    pub fn new() -> Self {
        DwarfUnwinder {
            vma_cache: HashMap::new(),
            elf_cache: HashMap::new(),
        }
    }

    /// Find which VMA contains the given address
    fn find_vma(vmas: &[VmaEntry], addr: u64) -> Option<&VmaEntry> {
        // VMAs are sorted by start address
        match vmas.binary_search_by_key(&addr, |v| v.start) {
            Ok(i) => Some(&vmas[i]),
            Err(0) => None,
            Err(i) => {
                let vma = &vmas[i - 1];
                if addr < vma.end {
                    Some(vma)
                } else {
                    None
                }
            }
        }
    }

    /// Load and cache .eh_frame for an ELF binary
    fn get_eh_frame(&mut self, path: &PathBuf) -> Option<&EhFrameCache> {
        if !self.elf_cache.contains_key(path) {
            let cache = load_eh_frame(path).ok();
            self.elf_cache.insert(path.clone(), cache);
        }
        self.elf_cache.get(path).and_then(|c| c.as_ref())
    }

    /// Unwind a user stack given registers and a raw stack dump.
    /// Returns a list of instruction pointers (return addresses).
    pub fn unwind(&mut self, pid: i32, rip: u64, rsp: u64, rbp: u64, stack: &[u8]) -> Vec<u64> {
        if rip == 0 || rsp == 0 || stack.is_empty() {
            return Vec::new();
        }

        let stack_base = rsp;
        let mut frames = Vec::with_capacity(MAX_FRAMES);
        let mut cur_rip = rip;
        let mut cur_rsp = rsp;
        let mut cur_rbp = rbp;
        let debug = std::env::var("RWALKER_DWARF_DEBUG").is_ok();

        // Make sure VMAs are loaded
        self.vma_cache
            .entry(pid)
            .or_insert_with(|| parse_maps(pid).unwrap_or_default());

        frames.push(cur_rip);

        for frame_idx in 0..MAX_FRAMES - 1 {
            // Find the VMA for current RIP — extract what we need to
            // avoid holding an immutable borrow on self.vma_cache
            let (path, load_base, vma_start, vma_end, vma_offset) = {
                let vmas = self.vma_cache.get(&pid).unwrap();
                match Self::find_vma(vmas, cur_rip) {
                    Some(v) => (v.path.clone(), v.start - v.offset, v.start, v.end, v.offset),
                    None => {
                        if debug {
                            eprintln!("  frame {frame_idx}: rip={cur_rip:#x} — no VMA found");
                        }
                        break;
                    }
                }
            };

            // Get .eh_frame for this binary
            let eh_cache = match self.get_eh_frame(&path) {
                Some(c) => c,
                None => {
                    if debug {
                        eprintln!(
                            "  frame {frame_idx}: rip={cur_rip:#x} path={} — no .eh_frame",
                            path.display()
                        );
                    }
                    break;
                }
            };

            // Convert runtime address to ELF virtual address.
            // Runtime addr = (load_base - elf_load_bias) + elf_vaddr
            // So: elf_vaddr = runtime_addr - load_base + elf_load_bias
            let relative_rip = cur_rip - load_base + eh_cache.elf_load_bias;

            if debug && frame_idx == 0 {
                eprintln!(
                    "dwarf unwind pid={pid} rip={cur_rip:#x} rsp={cur_rsp:#x} rbp={cur_rbp:#x}"
                );
                eprintln!(
                    "  vma: {:#x}-{:#x} offset={:#x} path={}",
                    vma_start,
                    vma_end,
                    vma_offset,
                    path.display()
                );
                eprintln!(
                    "  load_base={load_base:#x} relative_rip={relative_rip:#x} eh_frame_vaddr={:#x} text_vaddr={:#x}",
                    eh_cache.eh_frame_vaddr, eh_cache.text_vaddr
                );
            }

            // Parse .eh_frame
            let eh_frame_data = &eh_cache.mmap
                [eh_cache.eh_frame_offset..eh_cache.eh_frame_offset + eh_cache.eh_frame_len];
            let eh_frame = EhFrame::new(eh_frame_data, NativeEndian);

            let bases = BaseAddresses::default()
                .set_eh_frame(eh_cache.eh_frame_vaddr)
                .set_text(eh_cache.text_vaddr);

            let mut ctx = UnwindContext::new();

            // Look up unwind info for this address
            let row = match eh_frame.unwind_info_for_address(
                &bases,
                &mut ctx,
                relative_rip,
                EhFrame::cie_from_offset,
            ) {
                Ok(row) => row,
                Err(e) => {
                    if debug {
                        eprintln!(
                            "  frame {frame_idx}: rip={cur_rip:#x} relative={relative_rip:#x} — FDE lookup failed: {e}"
                        );
                    }
                    break;
                }
            };

            // Evaluate CFA
            let cfa =
                match row.cfa() {
                    CfaRule::RegisterAndOffset { register, offset } => {
                        let reg_val = get_reg(*register, cur_rsp, cur_rbp);
                        match reg_val {
                            Some(v) => {
                                if debug {
                                    eprintln!(
                                    "  frame {frame_idx}: CFA = reg{}({:#x}) + {offset} = {:#x}",
                                    register.0, v, (v as i64 + *offset) as u64
                                );
                                }
                                (v as i64 + *offset) as u64
                            }
                            None => {
                                if debug {
                                    eprintln!(
                                    "  frame {frame_idx}: CFA needs reg{} — not tracked, stopping",
                                    register.0
                                );
                                }
                                break;
                            }
                        }
                    }
                    _ => break, // Expression-based CFA not supported
                };

            // Recover return address
            let new_rip = match row.register(gimli::X86_64::RA) {
                RegisterRule::Undefined => break,
                RegisterRule::Offset(off) => {
                    let addr = (cfa as i64 + off) as u64;
                    match read_stack_u64(stack, stack_base, addr) {
                        Some(v) => {
                            if debug {
                                eprintln!(
                                    "  frame {frame_idx}: RA at CFA{off:+} = stack[{:#x}] = {v:#x}",
                                    addr
                                );
                            }
                            v
                        }
                        None => {
                            if debug {
                                eprintln!(
                                    "  frame {frame_idx}: RA at {addr:#x} outside stack dump ({stack_base:#x}..{:#x})",
                                    stack_base + stack.len() as u64
                                );
                            }
                            break;
                        }
                    }
                }
                RegisterRule::SameValue => cur_rip,
                RegisterRule::Register(r) => get_reg(r, cur_rsp, cur_rbp).unwrap_or(0),
                _ => break,
            };

            if new_rip == 0 {
                break;
            }

            // Recover caller's RBP
            let new_rbp = match row.register(gimli::X86_64::RBP) {
                RegisterRule::Offset(off) => {
                    let addr = (cfa as i64 + off) as u64;
                    read_stack_u64(stack, stack_base, addr).unwrap_or(cur_rbp)
                }
                RegisterRule::SameValue => cur_rbp,
                _ => cur_rbp,
            };

            // Caller's RSP is the CFA
            cur_rip = new_rip;
            cur_rsp = cfa;
            cur_rbp = new_rbp;

            frames.push(cur_rip);
        }

        frames
    }
}

fn get_reg(register: gimli::Register, rsp: u64, rbp: u64) -> Option<u64> {
    if register == gimli::X86_64::RSP {
        Some(rsp)
    } else if register == gimli::X86_64::RBP {
        Some(rbp)
    } else {
        None
    }
}

/// Read a u64 from the captured stack dump at a virtual address
fn read_stack_u64(stack: &[u8], stack_base: u64, addr: u64) -> Option<u64> {
    if addr < stack_base {
        return None;
    }
    let offset = (addr - stack_base) as usize;
    if offset + 8 > stack.len() {
        return None;
    }
    Some(u64::from_le_bytes(
        stack[offset..offset + 8].try_into().ok()?,
    ))
}

/// Parse /proc/<pid>/maps into VMA entries (only executable regions with file paths)
fn parse_maps(pid: i32) -> io::Result<Vec<VmaEntry>> {
    let path = format!("/proc/{pid}/maps");
    let file = fs::File::open(&path)?;
    let reader = io::BufReader::new(file);
    let mut vmas = Vec::new();

    for line in reader.lines() {
        let line = line?;
        // Format: start-end perms offset dev inode path
        let mut parts = line.splitn(6, char::is_whitespace);
        let range = match parts.next() {
            Some(r) => r,
            None => continue,
        };
        let perms = match parts.next() {
            Some(p) => p,
            None => continue,
        };
        // Only executable mappings with a file path
        if !perms.contains('x') {
            continue;
        }
        let offset_str = match parts.next() {
            Some(o) => o,
            None => continue,
        };
        let _dev = parts.next();
        let _inode = parts.next();
        let path_str = match parts.next() {
            Some(p) => p.trim(),
            None => continue,
        };
        if path_str.is_empty() || path_str.starts_with('[') {
            continue;
        }

        let (start_str, end_str) = match range.split_once('-') {
            Some(r) => r,
            None => continue,
        };
        let start = u64::from_str_radix(start_str, 16).unwrap_or(0);
        let end = u64::from_str_radix(end_str, 16).unwrap_or(0);
        let offset = u64::from_str_radix(offset_str, 16).unwrap_or(0);

        vmas.push(VmaEntry {
            start,
            end,
            offset,
            path: PathBuf::from(path_str),
        });
    }

    Ok(vmas)
}

/// Load .eh_frame section data from an ELF binary using manual ELF header parsing.
fn load_eh_frame(path: &PathBuf) -> io::Result<EhFrameCache> {
    let file = fs::File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let data = &mmap[..];

    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ELF"));
    }

    // ELF64 header
    let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(data[62..64].try_into().unwrap()) as usize;

    if e_shoff == 0 || e_shnum == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no section headers",
        ));
    }

    // Section header string table
    let shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstrtab_off = u64::from_le_bytes(
        data[shstrtab_hdr + 24..shstrtab_hdr + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    let shstrtab_size = u64::from_le_bytes(
        data[shstrtab_hdr + 32..shstrtab_hdr + 40]
            .try_into()
            .unwrap(),
    ) as usize;
    let shstrtab = &data[shstrtab_off..shstrtab_off + shstrtab_size];

    // Find the lowest PT_LOAD segment to compute the ELF load bias.
    // PT_LOAD = 1.  For PIE, the first LOAD has p_vaddr=0 p_offset=0
    // so bias=0.  For non-PIE or multi-segment layouts, bias = p_vaddr - p_offset
    // of the first LOAD segment.
    let mut elf_load_bias = 0u64;
    let mut found_load = false;
    for i in 0..e_phnum {
        let ph = e_phoff + i * e_phentsize;
        if ph + 56 > data.len() {
            break;
        }
        let p_type = u32::from_le_bytes(data[ph..ph + 4].try_into().unwrap());
        if p_type == 1 {
            // PT_LOAD
            let p_offset = u64::from_le_bytes(data[ph + 8..ph + 16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(data[ph + 16..ph + 24].try_into().unwrap());
            if !found_load {
                elf_load_bias = p_vaddr - p_offset;
                found_load = true;
            }
        }
    }

    let mut eh_frame_offset = 0usize;
    let mut eh_frame_len = 0usize;
    let mut eh_frame_vaddr = 0u64;
    let mut text_vaddr = 0u64;

    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        let sh_name = u32::from_le_bytes(data[sh..sh + 4].try_into().unwrap()) as usize;
        let sh_addr = u64::from_le_bytes(data[sh + 16..sh + 24].try_into().unwrap());
        let sh_offset = u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize;
        let sh_size = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize;

        // Get section name from string table
        let name_end = shstrtab[sh_name..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        let name = std::str::from_utf8(&shstrtab[sh_name..sh_name + name_end]).unwrap_or("");

        if name == ".eh_frame" {
            eh_frame_offset = sh_offset;
            eh_frame_len = sh_size;
            eh_frame_vaddr = sh_addr;
        } else if name == ".text" {
            text_vaddr = sh_addr;
        }
    }

    if eh_frame_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no .eh_frame section",
        ));
    }

    Ok(EhFrameCache {
        mmap,
        eh_frame_offset,
        eh_frame_len,
        eh_frame_vaddr,
        text_vaddr,
        elf_load_bias,
    })
}
