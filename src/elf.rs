//! Minimal pure-Rust ELF parser (32/64, little-endian) focused on what an
//! analysis agent needs: headers, sections, symbols, dynamic imports.

use crate::core::{shannon_entropy, Import, Section, Symbol};
use anyhow::{bail, Result};

#[allow(dead_code)]
pub struct Elf {
    pub is64: bool,
    pub machine: u16,
    pub r#type: u16,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u64,
    pub sections: Vec<Section>,
    pub symtab: Vec<Symbol>,
    pub dynsyms: Vec<Symbol>,
    pub verneed: Vec<String>, // needed version strings (e.g. GLIBC_2.34)
    /// dynamic string pairs: DT_SONAME, DT_RPATH, DT_RUNPATH ...
    pub dyn_strings: Vec<(String, String)>,
    /// Raw bytes of the `.dynamic` section for extended queries.
    pub dynamic_entries: Vec<(u64, u64)>, // (tag, value)
    interp: Option<String>,
}

impl Elf {
    pub fn parse(data: &[u8]) -> Result<Elf> {
        if data.len() < 64 {
            bail!("ELF too small");
        }
        let is64 = data[4] == 2;
        if data[5] != 1 {
            bail!("only little-endian ELF is supported");
        }

        let rd_u16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
        let rd_u32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let rd_u64 = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());

        let (machine, r#type, entry, phoff, shoff, flags) = if is64 {
            (
                rd_u16(18),
                rd_u16(16),
                rd_u64(24),
                rd_u64(32),
                rd_u64(40),
                rd_u64(48),
            )
        } else {
            (
                rd_u16(18),
                rd_u16(16),
                rd_u32(24) as u64,
                rd_u32(28) as u64,
                rd_u32(32) as u64,
                rd_u32(36) as u64,
            )
        };

        let (shentsize, shnum, shstrndx) = if is64 {
            (data[58] as usize, rd_u16(60) as usize, rd_u16(62))
        } else {
            (data[46] as usize, rd_u16(48) as usize, rd_u16(50))
        };

        if shnum > 0 && shoff as usize >= data.len() {
            bail!("bad section header table offset");
        }

        let mut sections = Vec::new();
        if shnum > 0 {
            if shstrndx as usize >= shnum {
                bail!("bad section name string table index");
            }
            let strtab_off =
                section_u64(data, shoff, shstrndx as usize, shentsize, is64, 3)? as usize;
            for i in 0..shnum {
                let h = shoff as usize + i * shentsize;
                if h + shentsize > data.len() {
                    break;
                }
                let (name_off, sh_type, sh_flags, addr, offset, size) = if is64 {
                    (
                        rd_u32(h) as usize,
                        rd_u32(h + 4),
                        rd_u64(h + 8),
                        rd_u64(h + 16),
                        rd_u64(h + 24),
                        rd_u64(h + 32),
                    )
                } else {
                    (
                        rd_u32(h) as usize,
                        rd_u32(h + 4),
                        rd_u32(h + 8) as u64,
                        rd_u32(h + 12) as u64,
                        rd_u32(h + 16) as u64,
                        rd_u32(h + 20) as u64,
                    )
                };
                let name = read_cstr(data, strtab_off + name_off);
                let memsz = size;
                let entropy = if sh_type != 8
                    && size > 0
                    && offset.saturating_add(size) as usize <= data.len()
                {
                    Some(shannon_entropy(
                        &data[offset as usize..(offset + size) as usize],
                    ))
                } else {
                    None
                };
                sections.push(Section {
                    kind: elf_section_kind(sh_type, &name),
                    name,
                    offset,
                    size,
                    memsz,
                    vaddr: addr,
                    flags: elf_section_flags(sh_flags),
                    entropy,
                });
            }
        }

        let find = |name: &str| sections.iter().find(|s| s.name == name);
        let symtab = find(".symtab")
            .map(|s| parse_symtab(data, s, &sections, is64, false))
            .unwrap_or_default();
        let dynsyms = find(".dynsym")
            .map(|s| parse_symtab(data, s, &sections, is64, true))
            .unwrap_or_default();

        // ---- dynamic info ----
        let mut verneed = Vec::new();
        let mut dyn_strings = Vec::new();
        let mut dynamic_entries = Vec::new();
        let mut interp = None;
        if let Some(sec) = find(".dynamic") {
            let strtab = find(".dynstr").map(|s| s.offset as usize).unwrap_or(0);
            let mut off = sec.offset as usize;
            let end = off + sec.size as usize;
            while off + (if is64 { 16 } else { 8 }) <= end && off + 16 <= data.len() {
                let (tag, val) = if is64 {
                    (rd_u64(off), rd_u64(off + 8))
                } else {
                    (rd_u32(off) as u64, rd_u32(off + 4) as u64)
                };
                if tag == 0 {
                    break;
                }
                dynamic_entries.push((tag, val));
                match tag {
                    1 /*DT_NEEDED*/ => dyn_strings.push((
                        "NEEDED".into(),
                        read_cstr(data, strtab + val as usize),
                    )),
                    14 /*DT_SONAME*/ => dyn_strings.push((
                        "SONAME".into(),
                        read_cstr(data, strtab + val as usize),
                    )),
                    15 /*DT_RPATH*/ => dyn_strings.push((
                        "RPATH".into(),
                        read_cstr(data, strtab + val as usize),
                    )),
                    29 /*DT_RUNPATH*/ => dyn_strings.push((
                        "RUNPATH".into(),
                        read_cstr(data, strtab + val as usize),
                    )),
                    _ => {}
                }
                off += if is64 { 16 } else { 8 };
            }
            let _ = strtab;
        }
        // program interpreter
        if let Some(p) = find(".interp") {
            interp = Some(read_cstr(data, p.offset as usize));
        }
        // DT_VERNEED section-based parse
        if let Some(v) = find(".gnu.version_r") {
            let strtab = find(".dynstr").map(|s| s.offset as usize).unwrap_or(0);
            let mut off = v.offset as usize;
            let end = off + v.size as usize;
            let entsz = 16usize;
            while off + entsz <= end && end <= data.len() {
                let _version = rd_u16(off);
                let cnt = rd_u16(off + 2);
                let file_off = rd_u32(off + 4) as usize; // vn_file
                let next = rd_u32(off + 8) as usize;
                let fname = read_cstr(data, strtab + file_off);
                verneed.push(fname);
                // aux entries: 16 bytes each on both classes? (hash, flags, other, name)
                for i in 0..cnt as usize {
                    let a = off + 16 + i * 16;
                    if a + 8 > end {
                        break;
                    }
                    let name_off = rd_u32(a + 4) as usize;
                    let _s = read_cstr(data, strtab + name_off);
                }
                if next == 0 {
                    break;
                }
                off += next;
            }
        }

        Ok(Elf {
            is64,
            machine,
            r#type,
            entry,
            phoff,
            shoff,
            flags,
            sections,
            symtab,
            dynsyms,
            verneed,
            dyn_strings,
            dynamic_entries,
            interp,
        })
    }

    pub fn interp(&self) -> Option<&str> {
        self.interp.as_deref()
    }

    /// Imported dynamic symbols (undefined in .dynsym).
    pub fn imports(&self) -> Vec<Import> {
        self.dynsyms
            .iter()
            .filter(|s| s.shndx == 0 && s.name != "$nd")
            .map(|s| Import {
                module: guess_module(&s.name),
                name: s.name.clone(),
                addr: s.addr,
            })
            .collect()
    }

    /// Exported dynamic symbols (defined in .dynsym).
    pub fn exports(&self) -> Vec<crate::core::Export> {
        self.dynsyms
            .iter()
            .filter(|s| s.addr != 0 && s.kind != "unknown")
            .map(|s| crate::core::Export {
                name: s.name.clone(),
                addr: s.addr,
            })
            .collect()
    }
}

// ---- helpers ----

/// Read a field from a section header by explicit byte offsets.
/// (name@0, type@4, flags@8/8, addr@16/12, offset@24/16, size@32/20 for 64/32)
fn section_u64(
    data: &[u8],
    shoff: u64,
    idx: usize,
    shentsize: usize,
    is64: bool,
    field: usize,
) -> Result<u64> {
    let h = shoff as usize + idx * shentsize;
    if h + shentsize > data.len() {
        bail!("section header out of bounds");
    }
    // byte offsets of sh_offset for each class
    let (off_field, sz_field) = if is64 {
        (24usize, 32usize)
    } else {
        (16usize, 20usize)
    };
    let byte_off = match field {
        3 => off_field,
        4 => sz_field,
        _ => anyhow::bail!("unsupported field {field}"),
    };
    Ok(if is64 {
        u64::from_le_bytes(data[h + byte_off..h + byte_off + 8].try_into()?)
    } else {
        u32::from_le_bytes(data[h + byte_off..h + byte_off + 4].try_into()?) as u64
    })
}

fn parse_symtab(
    data: &[u8],
    sec: &Section,
    sections: &[Section],
    is64: bool,
    is_dyn: bool,
) -> Vec<Symbol> {
    let strtab = sections
        .iter()
        .find(|s| s.name == if is_dyn { ".dynstr" } else { ".strtab" })
        .map(|s| s.offset as usize)
        .unwrap_or(0);
    let entsz: usize = if is64 { 24 } else { 16 };
    let mut out = Vec::new();
    let mut off = sec.offset as usize;
    let end = off + sec.size as usize;
    while off + entsz <= end && off + entsz <= data.len() {
        let (name_off, info, other, shndx, value, size) = if is64 {
            (
                u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize,
                data[off + 4],
                data[off + 5],
                u16::from_le_bytes([data[off + 6], data[off + 7]]),
                u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()),
                u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize,
                data[off + 12],
                data[off + 13],
                u16::from_le_bytes([data[off + 14], data[off + 15]]),
                u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as u64,
                u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as u64,
            )
        };
        let _ = other;
        if name_off != 0 || value != 0 {
            let name = read_cstr(data, strtab + name_off);
            if !name.is_empty() {
                let bind = match info >> 4 {
                    0 => "local",
                    1 => "global",
                    2 => "weak",
                    _ => "unknown",
                };
                let kind = match info & 0xf {
                    0 => "unknown", // NOTYPE: imports live here
                    1 => "object",
                    2 => "func",
                    3 => "section",
                    4 => "file",
                    _ => "unknown",
                };
                let section = if shndx > 0 && (shndx as usize) < sections.len() {
                    Some(sections[shndx as usize].name.clone())
                } else {
                    None
                };
                out.push(Symbol {
                    name,
                    addr: value,
                    size,
                    kind: kind.to_string(),
                    bind: bind.to_string(),
                    section,
                    source: if is_dyn {
                        "dynsym".to_string()
                    } else {
                        "symtab".to_string()
                    },
                    shndx,
                });
            }
        }
        off += entsz;
    }
    out
}

fn guess_module(name: &str) -> String {
    // crude lib guess for ELF imports: strip the version suffix
    let base = name.split('@').next().unwrap_or(name);
    if base.starts_with("__libc") || base.starts_with("_IO") {
        "libc.so.6".into()
    } else if base.starts_with("pthread") {
        "libpthread.so.0".into()
    } else {
        "-".into()
    }
}

fn elf_section_kind(sh_type: u32, name: &str) -> String {
    match sh_type {
        8 => "bss".into(),
        _ => match name {
            ".text" => "code".into(),
            ".rodata" | ".data.rel.ro" | ".eh_frame_hdr" => "rodata".into(),
            ".data" => "data".into(),
            n if n.starts_with(".debug") || n.starts_with(".zdebug") => "debug".into(),
            _ => "other".into(),
        },
    }
}

fn elf_section_flags(flags: u64) -> String {
    let mut s = Vec::new();
    if flags & 1 != 0 {
        s.push("W");
    }
    if flags & 2 != 0 {
        s.push("A");
    }
    if flags & 4 != 0 {
        s.push("X");
    }
    if flags & 0xf0000000 != 0 {
        s.push("o");
    }
    if s.is_empty() {
        "-".into()
    } else {
        s.join("")
    }
}

fn read_cstr(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[off..end]).into_owned()
}
