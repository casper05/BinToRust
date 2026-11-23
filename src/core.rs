//! Unified binary container: ELF (32/64) or PE (32/64).
//!
//! `Binary` is a facade: format detection, vaddr<->offset mapping and
//! delegating to the ELF / PE backends parsed eagerly at load time.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::elf::Elf;
use crate::pe::Pe;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Elf,
    Pe,
}

impl Format {
    pub fn name(&self) -> &'static str {
        match self {
            Format::Elf => "elf",
            Format::Pe => "pe",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Arch {
    X86,
    X64,
    Arm,
    AArch64,
    Unknown(u16),
}

impl Arch {
    pub fn name(&self) -> String {
        match self {
            Arch::X86 => "x86".into(),
            Arch::X64 => "x64".into(),
            Arch::Arm => "arm".into(),
            Arch::AArch64 => "arm64".into(),
            Arch::Unknown(v) => format!("unknown(0x{v:04x})"),
        }
    }
}

/// A section-like region: file offset, virtual address, sizes, flags.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub kind: String, // code | data | rodata | bss | debug | other
    pub offset: u64,
    pub size: u64,  // file (raw) size
    pub memsz: u64, // memory size (PE VirtualSize; ELF == size)
    pub vaddr: u64,
    pub flags: String,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String, // func | object | section | file | unknown
    pub bind: String, // local | global | weak
    pub section: Option<String>,
    pub source: String, // symtab | dynsym | exports
    #[serde(skip_serializing)]
    pub shndx: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub name: String,
    pub addr: u64,
}

pub struct Binary {
    pub data: Vec<u8>,
    pub path: String,
    pub format: Format,
    pub elf: Option<Elf>,
    pub pe: Option<Pe>,
}

impl Binary {
    /// Load and parse a binary file.
    pub fn load(path: &str) -> Result<Binary> {
        let data = std::fs::read(path).with_context(|| format!("cannot read {path}"))?;
        Binary::from_data(data, path)
    }

    pub fn from_data(data: Vec<u8>, path: &str) -> Result<Binary> {
        if data.len() < 16 {
            bail!("file too small ({ } bytes): {path}", data.len());
        }
        let (format, elf, pe) = if &data[0..4] == b"\x7fELF" {
            let e = Elf::parse(&data).context("failed to parse ELF")?;
            (Format::Elf, Some(e), None)
        } else if data[0] == b'M' && data[1] == b'Z' {
            let p = Pe::parse(&data).context("failed to parse PE")?;
            (Format::Pe, None, Some(p))
        } else {
            bail!(
                "unsupported format (magic: {}): {path}",
                hex::encode(&data[0..4])
            );
        };
        Ok(Binary {
            data,
            path: path.to_string(),
            format,
            elf,
            pe,
        })
    }

    pub fn arch(&self) -> Arch {
        match (&self.elf, &self.pe) {
            (Some(e), _) => match e.machine {
                3 => Arch::X86,
                62 => Arch::X64,
                40 => Arch::Arm,
                183 => Arch::AArch64,
                m => Arch::Unknown(m),
            },
            (_, Some(p)) => match p.machine {
                0x014c => Arch::X86,
                0x8664 => Arch::X64,
                0x01c0 | 0x01c4 => Arch::Arm,
                0xaa64 => Arch::AArch64,
                m => Arch::Unknown(m),
            },
            _ => Arch::Unknown(0),
        }
    }

    pub fn is_64(&self) -> bool {
        match (&self.elf, &self.pe) {
            (Some(e), _) => e.is64,
            (_, Some(p)) => p.is64,
            _ => false,
        }
    }

    pub fn entry(&self) -> u64 {
        match (&self.elf, &self.pe) {
            (Some(e), _) => e.entry,
            (_, Some(p)) => p.entry,
            _ => 0,
        }
    }

    pub fn image_base(&self) -> u64 {
        match (&self.elf, &self.pe) {
            (Some(_), _) => 0,
            (_, Some(p)) => p.image_base,
            _ => 0,
        }
    }

    pub fn sections(&self) -> &[Section] {
        match (&self.elf, &self.pe) {
            (Some(e), _) => &e.sections,
            (_, Some(p)) => &p.sections,
            _ => &[],
        }
    }

    /// All symbols (ELF: symtab + dynsym; PE: exports).
    pub fn symbols(&self) -> Vec<Symbol> {
        match (&self.elf, &self.pe) {
            (Some(e), _) => e.symtab.iter().chain(e.dynsyms.iter()).cloned().collect(),
            (_, Some(p)) => p
                .exports
                .iter()
                .map(|ex| Symbol {
                    name: ex.name.clone(),
                    addr: ex.addr,
                    size: 0,
                    kind: "func".into(),
                    bind: "global".into(),
                    section: Some(".text".into()),
                    source: "exports".into(),
                    shndx: 1,
                })
                .collect(),
            _ => vec![],
        }
    }

    pub fn imports(&self) -> Vec<Import> {
        match (&self.elf, &self.pe) {
            (Some(e), _) => e.imports(),
            (_, Some(p)) => p.imports.clone(),
            _ => vec![],
        }
    }

    pub fn exports(&self) -> Vec<Export> {
        match (&self.elf, &self.pe) {
            (Some(e), _) => e.exports(),
            (_, Some(p)) => p.exports.clone(),
            _ => vec![],
        }
    }

    /// Find a symbol by exact name (or by `name+N` / `name+N bytes`).
    pub fn find_symbol(&self, name: &str) -> Option<(u64, u64)> {
        for s in self.symbols() {
            if s.name == name {
                return Some((s.addr, s.size));
            }
        }
        // PE exports are stored without the leading underscore in some toolchains
        if self.format == Format::Pe && !name.starts_with('_') {
            for s in self.symbols() {
                if s.name.trim_start_matches('_') == name {
                    return Some((s.addr, s.size));
                }
            }
        }
        None
    }

    /// Resolve a start specification: hex address (`0x401000`), decimal
    /// address, or a symbol name.
    pub fn resolve_start(&self, spec: &str) -> Result<u64> {
        if let Some(hexpart) = spec.strip_prefix("0x").or_else(|| spec.strip_prefix("0X")) {
            if let Ok(v) = u64::from_str_radix(hexpart, 16) {
                return Ok(v);
            }
        }
        if let Ok(v) = spec.parse::<u64>() {
            return Ok(v);
        }
        match self.find_symbol(spec) {
            Some((addr, _)) => Ok(addr),
            None => bail!("symbol not found: {spec}"),
        }
    }

    /// Convert a virtual address to a file offset.
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Result<u64> {
        if let Some(p) = &self.pe {
            let rva = vaddr.checked_sub(p.image_base).unwrap_or(vaddr);
            return p.rva_to_offset(rva);
        }
        // ELF
        for s in self.sections() {
            if s.kind == "bss" {
                continue;
            }
            if s.vaddr <= vaddr && vaddr < s.vaddr + s.size.max(s.memsz) {
                if vaddr - s.vaddr >= s.size {
                    bail!("vaddr {vaddr:#x} is in the virtual-only part of {}", s.name);
                }
                return Ok(s.offset + (vaddr - s.vaddr));
            }
        }
        bail!("vaddr {vaddr:#x} is not mapped to any section")
    }

    /// Convert a file offset to a virtual address.
    pub fn offset_to_vaddr(&self, offset: u64) -> Result<u64> {
        if let Some(p) = &self.pe {
            for s in p.sections.iter() {
                if s.offset <= offset && offset < s.offset + s.size {
                    return Ok(p.image_base + s.vaddr + (offset - s.offset));
                }
            }
            if offset < p.size_of_headers as u64 {
                return Ok(p.image_base + offset);
            }
            bail!("offset {offset:#x} is not inside any section")
        }
        for s in self.sections() {
            if s.offset <= offset && offset < s.offset + s.size {
                return Ok(s.vaddr + (offset - s.offset));
            }
        }
        bail!("offset {offset:#x} is not inside any section")
    }

    pub fn read_at(&self, offset: u64, len: u64) -> Result<&[u8]> {
        let start = offset as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or_else(|| anyhow::anyhow!("length overflow"))?;
        if end > self.data.len() {
            bail!(
                "read out of bounds: offset {offset:#x} + len {len:#x} > file size {:#x}",
                self.data.len()
            );
        }
        Ok(&self.data[start..end])
    }

    #[allow(dead_code)]
    pub fn read_vaddr(&self, vaddr: u64, len: u64) -> Result<&[u8]> {
        let off = self.vaddr_to_offset(vaddr)?;
        self.read_at(off, len)
    }

    pub fn file_size(&self) -> u64 {
        self.data.len() as u64
    }
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / total;
            h -= p * p.log2();
        }
    }
    h
}
