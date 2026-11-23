//! Analysis commands: inspect, sections, symbols, imports, exports, strings,
//! hex, hash, disasm.

use crate::core::{shannon_entropy, Binary};
use crate::disasm::Decoder;
use crate::out::{hex_dump, Out, Table};
use anyhow::{bail, Context, Result};
use serde::Serialize;

pub fn inspect(bin: &Binary) -> Result<Out> {
    let arch = bin.arch();
    let secs = bin.sections();
    let code_secs: Vec<&crate::core::Section> = secs.iter().filter(|s| s.kind == "code").collect();
    let mut info = serde_json::json!({
        "path": bin.path,
        "format": bin.format.name(),
        "arch": arch.name(),
        "bits": if bin.is_64() { 64 } else { 32 },
        "file_size": bin.file_size(),
        "entry": format!("{:#x}", bin.entry()),
        "image_base": format!("{:#x}", bin.image_base()),
        "sections": secs.len(),
        "symbols": bin.symbols().len(),
        "imports": bin.imports().len(),
        "exports": bin.exports().len(),
    });
    match (&bin.elf, &bin.pe) {
        (Some(e), _) => {
            info["elf_type"] = serde_json::json!(elf_type_name(e.r#type));
            info["machine"] = serde_json::json!(elf_machine_name(e.machine));
            if let Some(i) = e.interp() {
                info["interpreter"] = serde_json::json!(i);
            }
            if !e.dyn_strings.is_empty() {
                info["dynamic"] = serde_json::json!(e.dyn_strings);
            }
            let with_symtab = e.symtab.len();
            info["symtab_symbols"] = serde_json::json!(with_symtab);
            info["dynsym_symbols"] = serde_json::json!(e.dynsyms.len());
        }
        (None, Some(p)) => {
            info["machine"] = serde_json::json!(pe_machine_name(p.machine));
            info["subsystem"] = serde_json::json!(subsystem_name(p.subsystem));
            info["timestamp"] = serde_json::json!(p.timestamp);
            info["dll_characteristics"] =
                serde_json::json!(format!("{:#06x}", p.dll_characteristics));
            let flags = pe_dll_chars(p.dll_characteristics);
            if !flags.is_empty() {
                info["mitigations"] = serde_json::json!(flags);
            }
            info["entry_rva"] = serde_json::json!(format!("{:#x}", p.entry - p.image_base));
            if !p.version_info.is_empty() {
                let vi: serde_json::Map<String, serde_json::Value> = p
                    .version_info
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::json!(v)))
                    .collect();
                info["version_info"] = serde_json::json!(vi);
            }
            if let Some(dn) = &p.dotnet {
                info["dotnet"] = serde_json::json!({
                    "runtime_version": dn.runtime_version,
                    "flags": dn.flags,
                    "metadata_rva": format!("{:#x}", dn.metadata_rva),
                    "metadata_size": dn.metadata_size,
                    "entry_point_token": dn.entry_point_token,
                });
            }
        }
        _ => {}
    }
    // packed / entropy heuristic
    let mut high_entropy: Vec<String> = vec![];
    for s in secs {
        if let Some(e) = s.entropy {
            if e > 7.0 && s.size > 4096 && s.kind != "debug" {
                high_entropy.push(format!("{} ({e:.2})", s.name));
            }
        }
    }
    if !high_entropy.is_empty() {
        info["high_entropy_sections"] = serde_json::json!(high_entropy);
        info["possibly_packed"] = serde_json::json!(true);
    }
    let _ = code_secs;
    Ok(Out::json(&info))
}

fn elf_type_name(t: u16) -> String {
    match t {
        1 => "relocatable".into(),
        2 => "executable".into(),
        3 => "shared".into(),
        4 => "core".into(),
        _ => format!("unknown({t})"),
    }
}

fn elf_machine_name(m: u16) -> String {
    match m {
        3 => "x86".into(),
        62 => "x86-64".into(),
        40 => "arm".into(),
        183 => "aarch64".into(),
        _ => format!("unknown({m})"),
    }
}

fn pe_machine_name(m: u16) -> String {
    match m {
        0x014c => "i386".into(),
        0x8664 => "amd64".into(),
        0x01c0 => "arm".into(),
        0xaa64 => "arm64".into(),
        _ => format!("unknown({m:#x})"),
    }
}

fn subsystem_name(s: u16) -> String {
    match s {
        1 => "native".into(),
        2 => "windows-gui".into(),
        3 => "windows-console".into(),
        7 => "posix-cui".into(),
        14 => "xbox".into(),
        _ => format!("unknown({s})"),
    }
}

fn pe_dll_chars(c: u16) -> Vec<String> {
    let mut v = vec![];
    if c & 0x0020 != 0 {
        v.push("high-entropy-va".into());
    }
    if c & 0x0040 != 0 {
        v.push("dynamic-base".into());
    }
    if c & 0x0100 != 0 {
        v.push("nx-compatible".into());
    }
    if c & 0x0400 != 0 {
        v.push("no-isolation".into());
    }
    if c & 0x1000 != 0 {
        v.push("no-seh".into());
    }
    if c & 0x4000 != 0 {
        v.push("guard-cf".into());
    }
    if c & 0x8000 != 0 {
        v.push("terminal-server-aware".into());
    }
    v
}

pub fn sections(bin: &Binary, json: bool) -> Result<Out> {
    let secs = bin.sections();
    if json {
        Ok(Out::json(&secs))
    } else {
        let mut t = Table::new(&[
            "name", "kind", "vaddr", "off", "size", "memsz", "flags", "entropy",
        ]);
        for s in secs {
            t.row(vec![
                s.name.clone(),
                s.kind.clone(),
                format!("{:#x}", s.vaddr),
                format!("{:#x}", s.offset),
                format!("{:#x}", s.size),
                format!("{:#x}", s.memsz),
                s.flags.clone(),
                s.entropy
                    .map(|e| format!("{e:.2}"))
                    .unwrap_or_else(|| "-".into()),
            ]);
        }
        Ok(Out::text(t.render()))
    }
}

pub fn symbols(
    bin: &Binary,
    filter: &str,
    kind: Option<&str>,
    limit: Option<usize>,
    json: bool,
) -> Result<Out> {
    let mut syms = bin.symbols();
    if !filter.is_empty() {
        let f = filter.to_lowercase();
        syms.retain(|s| s.name.to_lowercase().contains(&f));
    }
    if let Some(k) = kind {
        syms.retain(|s| s.kind == k);
    }
    syms.sort_by_key(|s| s.addr);
    let total = syms.len();
    if let Some(l) = limit {
        syms.truncate(l);
    }
    if json {
        if limit.is_some() {
            Ok(Out::json(&serde_json::json!({
                "total": total,
                "shown": syms.len(),
                "symbols": syms,
            })))
        } else {
            Ok(Out::json(&syms))
        }
    } else {
        let mut t = Table::new(&["addr", "size", "kind", "bind", "section", "src", "name"]);
        for s in &syms {
            t.row(vec![
                format!("{:#x}", s.addr),
                format!("{:#x}", s.size),
                s.kind.clone(),
                s.bind.clone(),
                s.section.clone().unwrap_or_else(|| "-".into()),
                s.source.clone(),
                s.name.clone(),
            ]);
        }
        let mut out = String::new();
        if limit.is_some() && syms.len() < total {
            out.push_str(&format!("showing {} of {total} symbols\n", syms.len()));
        }
        out.push_str(&t.render());
        Ok(Out::text(out))
    }
}

pub fn imports(bin: &Binary, json: bool) -> Result<Out> {
    let imps = bin.imports();
    if json {
        Ok(Out::json(&imps))
    } else {
        let mut t = Table::new(&["module", "name", "addr"]);
        for i in &imps {
            t.row(vec![
                i.module.clone(),
                i.name.clone(),
                format!("{:#x}", i.addr),
            ]);
        }
        Ok(Out::text(t.render()))
    }
}

/// PE resource tree: type / name / language levels + data leaves.
pub fn resources(bin: &Binary, json: bool) -> Result<Out> {
    let Some(pe) = &bin.pe else {
        bail!("resources are a PE concept (this binary is not PE)");
    };
    // re-walk the tree from the raw file data
    let pe_off = u32::from_le_bytes(bin.data[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe_off + 24;
    let magic = u16::from_le_bytes(bin.data[opt..opt + 2].try_into().unwrap());
    let is64 = magic == 0x20b;
    let entries =
        crate::pe::parse_resource_tree(&bin.data, opt, is64, &pe.sections, pe.size_of_headers);
    if json {
        Ok(Out::json(&entries))
    } else {
        let mut t = Table::new(&["level", "id/name", "type", "rva", "offset", "size", "lang"]);
        for e in &entries {
            t.row(vec![
                e.level.to_string(),
                e.id.clone(),
                e.type_name.clone().unwrap_or_else(|| "-".into()),
                e.rva
                    .map(|v| format!("{v:#x}"))
                    .unwrap_or_else(|| "-".into()),
                e.offset
                    .map(|v| format!("{v:#x}"))
                    .unwrap_or_else(|| "-".into()),
                e.size.map(|v| format!("{v}")).unwrap_or_else(|| "-".into()),
                e.lang.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            ]);
        }
        let mut out = format!("resource tree: {} entries\n", entries.len());
        out.push_str(&t.render());
        Ok(Out::text(out))
    }
}

/// Function boundaries in code sections: prologue detection + symbol hints.
/// A "function" starts at a compiler prologue (push ebp/rbp; mov ebp/rsp,
/// stack-pointer adjustment, or a known symbol) and ends before the next
/// start or at the section end.
#[derive(Serialize)]
struct FuncEntry {
    addr: String,
    offset: String,
    /// how this start was detected: prologue-ebp | prologue-rsp | symbol
    origin: String,
    /// symbol name when the start coincides with one
    symbol: Option<String>,
    /// bytes from start to the next start (upper bound, includes padding)
    size: u64,
}

pub fn functions(bin: &Binary, json: bool, limit: Option<usize>) -> Result<Out> {
    let arch = bin.arch();
    if !matches!(arch, crate::core::Arch::X86 | crate::core::Arch::X64) {
        bail!(
            "function detection needs x86/x64 code (got {})",
            arch.name()
        );
    }
    let dec = crate::disasm::Decoder::new(bin);
    let mut funcs: Vec<FuncEntry> = Vec::new();

    for sec in bin.sections().iter().filter(|s| s.kind == "code") {
        let start = sec.offset as usize;
        let end = start.saturating_add(sec.size as usize).min(bin.data.len());
        if start + 8 > end {
            continue;
        }
        let data = &bin.data[start..end];
        let base = sec.vaddr;
        let mut starts: Vec<(u64, &'static str)> = Vec::new();
        let mut i = 0usize;
        while i + 3 < data.len() {
            let b0 = data[i];
            let b1 = data.get(i + 1).copied().unwrap_or(0);
            let b2 = data.get(i + 2).copied().unwrap_or(0);
            let b3 = data.get(i + 3).copied().unwrap_or(0);
            let detected: Option<&'static str> = if bin.is_64() {
                match (b0, b1, b2) {
                    // push rbp; mov rbp, rsp  (55 48 89 E5)
                    (0x55, 0x48, 0x89) if b3 == 0xe5 => Some("prologue-ebp"),
                    // endbr64 (F3 0F 1E FA) — indirect-branch landing pad
                    (0xf3, 0x0f, 0x1e) if b3 == 0xfa => Some("endbr64"),
                    _ => None,
                }
            } else {
                match (b0, b1) {
                    // push ebp; mov ebp, esp  (55 89 EC / 55 8B EC)
                    (0x55, 0x89) if b2 == 0xec => Some("prologue-ebp"),
                    (0x55, 0x8b) if b2 == 0xec => Some("prologue-ebp"),
                    _ => None,
                }
            };
            if let Some(kind) = detected {
                let va = base + i as u64;
                if let Some((last, _)) = starts.last() {
                    // skip a zero-length run: prologues closer than 8 bytes
                    // are almost surely data (jump tables)
                    if va - last < 8 {
                        i += 1;
                        continue;
                    }
                }
                starts.push((va, kind));
                i += 4;
            } else {
                i += 1;
            }
        }
        // merge with symbols: any symbol inside this section whose address is
        // not already a detected start becomes a start of origin "symbol"
        for (addr, _sz, _name) in dec.symbol_list() {
            let addr = *addr;
            if addr >= base
                && addr < base + data.len() as u64
                && !starts.iter().any(|(a, _)| *a == addr)
            {
                starts.push((addr, "symbol"));
            }
        }
        starts.sort();
        starts.dedup_by_key(|(a, _)| *a);
        for (idx, (va, kind)) in starts.iter().enumerate() {
            let next = starts
                .get(idx + 1)
                .map(|(a, _)| *a)
                .unwrap_or(base + data.len() as u64);
            let sym = dec.symbol_at(*va).map(|(n, d)| {
                if d == 0 {
                    n.to_string()
                } else {
                    format!("{n}+{d:#x}")
                }
            });
            funcs.push(FuncEntry {
                addr: format!("{va:#x}"),
                offset: format!("{:#x}", *va - base + sec.offset),
                origin: kind.to_string(),
                symbol: sym,
                size: next - va,
            });
        }
    }
    let total = funcs.len();
    if let Some(l) = limit {
        funcs.truncate(l);
    }
    if json {
        Ok(Out::json(&serde_json::json!({
            "total": total,
            "shown": funcs.len(),
            "functions": funcs,
        })))
    } else {
        let mut t = Table::new(&["addr", "size", "origin", "symbol"]);
        for f in &funcs {
            t.row(vec![
                f.addr.clone(),
                f.size.to_string(),
                f.origin.clone(),
                f.symbol.clone().unwrap_or_else(|| "-".into()),
            ]);
        }
        let mut out = format!("functions: {total}\n");
        out.push_str(&t.render());
        Ok(Out::text(out))
    }
}

pub fn exports(bin: &Binary, json: bool) -> Result<Out> {
    let exps = bin.exports();
    if json {
        Ok(Out::json(&exps))
    } else {
        let mut t = Table::new(&["addr", "name"]);
        for e in &exps {
            t.row(vec![format!("{:#x}", e.addr), e.name.clone()]);
        }
        Ok(Out::text(t.render()))
    }
}

#[derive(Serialize)]
struct StrEntry {
    offset: u64,
    vaddr: Option<u64>,
    len: usize,
    text: String,
    section: Option<String>,
}

pub fn strings(
    bin: &Binary,
    min_len: usize,
    filter: &str,
    limit: Option<usize>,
    utf16: bool,
    json: bool,
) -> Result<Out> {
    if min_len < 2 {
        bail!("minimum length is 2");
    }
    let mut out = Vec::new();
    let data = &bin.data;
    if utf16 {
        // UTF-16LE: 2-byte units. Beyond the ASCII subset this accepts real
        // text code points — Cyrillic, Greek, CJK and friends — so Windows
        // string literals in those scripts are no longer dropped (they were
        // silently lost before, while GNU `strings -e l` extracts them).
        // Non-ASCII units are only accepted on even file offsets: reading
        // ASCII bytes at odd offsets produces pseudo-CJK garbage pairs
        // (e.g. 0x696d from "mi"), which flooded the output on plain ELF
        // binaries. ASCII units (high byte 0) are safe at any offset.
        let printable_ascii_unit = |u: u16| -> bool { matches!(u, 0x09 | 0x20..=0x7e) };
        let printable_text_unit = |u: u16| -> bool {
            // CJK-range units whose BOTH bytes are printable ASCII are
            // almost certainly an ASCII pair misread as UTF-16 ("am" =
            // 0x616d); a real ideograph always has a non-ASCII byte
            match u {
                0x4e00..=0x9fff
                    if ((u & 0xff) as u8 as char).is_ascii_alphabetic()
                        && ((u >> 8) as u8 as char).is_ascii_alphabetic() =>
                {
                    false
                }
                // Latin-1 letters and symbols (no C1 controls)
                0xa0..=0xff
                // Latin Extended
                | 0x100..=0x17f
                // Greek
                | 0x370..=0x3ff
                // Cyrillic + Cyrillic Supplement
                | 0x400..=0x52f
                // Hebrew
                | 0x590..=0x5ff
                // Arabic
                | 0x600..=0x6ff
                // Hiragana / Katakana
                | 0x3040..=0x30ff
                // CJK Unified Ideographs
                | 0x4e00..=0x9fff => true,
                _ => false,
            }
        };
        let mut start: Option<usize> = None;
        let mut i = 0usize;
        while i + 1 < data.len() {
            let u = u16::from_le_bytes([data[i], data[i + 1]]);
            let ok = if i.is_multiple_of(2) {
                printable_ascii_unit(u) || printable_text_unit(u)
            } else {
                printable_ascii_unit(u)
            };
            if ok {
                if start.is_none() {
                    start = Some(i);
                }
                i += 2;
            } else {
                if let Some(s) = start {
                    if (i - s) / 2 >= min_len {
                        push_string_utf16(bin, &mut out, s, i, min_len);
                    }
                }
                start = None;
                // resync to a 2-byte boundary from a non-printable unit
                i += 1;
            }
        }
        if let Some(s) = start {
            let end = data.len() - (data.len() - s) % 2;
            if (end - s) / 2 >= min_len {
                push_string_utf16(bin, &mut out, s, end, min_len);
            }
        }
    } else {
        let mut start: Option<usize> = None;
        for (i, &b) in data.iter().enumerate() {
            let printable = b == 0x09 || (0x20..0x7f).contains(&b);
            if printable {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start {
                if i - s >= min_len {
                    push_string(bin, &mut out, s, i);
                }
                start = None;
            }
        }
        if let Some(s) = start {
            if data.len() - s >= min_len {
                push_string(bin, &mut out, s, data.len());
            }
        }
    }
    if !filter.is_empty() {
        let f = filter.to_lowercase();
        out.retain(|e: &StrEntry| e.text.to_lowercase().contains(&f));
    }
    let total = out.len();
    if let Some(l) = limit {
        out.truncate(l);
    }
    if json {
        if limit.is_some() {
            Ok(Out::json(&serde_json::json!({
                "total": total,
                "shown": out.len(),
                "encoding": if utf16 { "utf-16le" } else { "ascii" },
                "strings": out,
            })))
        } else {
            Ok(Out::json(&out))
        }
    } else {
        let mut s = String::new();
        if limit.is_some() && out.len() < total {
            s.push_str(&format!(
                "showing {} of {total} strings ({})\n",
                out.len(),
                if utf16 { "utf-16le" } else { "ascii" }
            ));
        }
        for e in &out {
            match e.vaddr {
                Some(v) => s.push_str(&format!("{:>10} {:#012x} {}\n", e.offset, v, e.text)),
                None => s.push_str(&format!("{:>10} {}\n", e.offset, e.text)),
            }
        }
        Ok(Out::text(s))
    }
}

fn push_string(bin: &Binary, out: &mut Vec<StrEntry>, s: usize, e: usize) {
    let text = String::from_utf8_lossy(&bin.data[s..e]).into_owned();
    let section = bin
        .sections()
        .iter()
        .find(|sec| (sec.offset as usize) <= s && s < (sec.offset + sec.size) as usize)
        .map(|sec| sec.name.clone());
    let vaddr = bin.offset_to_vaddr(s as u64).ok();
    out.push(StrEntry {
        offset: s as u64,
        vaddr,
        len: e - s,
        text,
        section,
    });
}

/// Same as `push_string`, but decodes the range as UTF-16LE first (every
/// second byte is 0 for the ASCII subset we extracted).
#[allow(clippy::too_many_arguments)]
/// Classify a code point into a script bucket for the coherence filter.
/// Returns None for ASCII (counted separately): ASCII is script-neutral and
/// never penalizes a string.
fn script_of(c: char) -> Option<&'static str> {
    match c {
        '\u{00a0}'..='\u{024f}' => Some("latin"), // Latin-1 + Extended
        '\u{0370}'..='\u{03ff}' => Some("greek"),
        '\u{0400}'..='\u{052f}' => Some("cyrillic"),
        '\u{0530}'..='\u{058f}' => Some("armenian"),
        '\u{0590}'..='\u{05ff}' => Some("hebrew"),
        '\u{0600}'..='\u{06ff}' => Some("arabic"),
        '\u{0e00}'..='\u{0e7f}' => Some("thai"),
        '\u{3040}'..='\u{30ff}' => Some("kana"),
        '\u{4e00}'..='\u{9fff}' => Some("cjk"),
        '\u{ac00}'..='\u{d7af}' => Some("hangul"),
        _ => None,
    }
}

/// Coherence filter: a string is *text-like* when at least 60% of its
/// non-ASCII code points fall into a single script, or it is pure ASCII.
/// Data blocks misread as UTF-16 produce a chaotic mix of unrelated scripts
/// (e.g. pseudo-CJK gluing), which this rejects; real Windows strings in one
/// language pass. ASCII-pair gluing (every unit printable ASCII) is also
/// accepted — it matches GNU `strings -e l` behavior.
fn utf16_text_coherent(text: &str, min_len: usize) -> bool {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < min_len {
        return false;
    }
    let mut scripts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    let mut non_ascii = 0usize;
    for &c in &chars {
        if let Some(sc) = script_of(c) {
            *scripts.entry(sc).or_insert(0) += 1;
            non_ascii += 1;
        } else if !c.is_ascii() {
            // symbol/punctuation from other planes: count as noise
            non_ascii += 1;
            *scripts.entry("other").or_insert(0) += 1;
        }
    }
    if non_ascii == 0 {
        return true; // pure printable ASCII — same as GNU strings
    }
    let total = chars.len();
    let best = scripts.values().copied().max().unwrap_or(0);
    // A genuine non-ASCII string is dominated by its script: >= 60% of ALL
    // characters in one script. Strings with a token non-ASCII sprinkle
    // (e.g. 2 pseudo-CJK units glued to 10 ASCII bytes) are data noise.
    if best * 10 >= total * 6 {
        return true;
    }
    // Mixed ASCII + one script is also common in real UI strings
    // ("Путь к файлу: %s"), but then non-ASCII must be a visible fraction.
    best * 4 >= total && non_ascii * 100 >= total * 25
}

fn push_string_utf16(bin: &Binary, out: &mut Vec<StrEntry>, s: usize, e: usize, _min_len: usize) {
    // decode full UTF-16LE units to UTF-8 (Cyrillic/CJK included), keeping
    // lone surrogates as U+FFFD via from_utf8_lossy semantics
    let units: Vec<u16> = bin.data[s..e]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let text = String::from_utf16_lossy(&units);
    // Non-ASCII content gets an extra gate: real Windows strings in a
    // non-Latin script are almost always NUL-terminated; code bytes glued
    // into pseudo-CJK (x86 .text pairs) are not. Pure-ASCII strings keep the
    // GNU-compatible behavior (accepted regardless of terminator).
    let has_non_ascii = !text.is_ascii();
    if has_non_ascii {
        // Non-ASCII text is accepted only when the run is NUL-terminated
        // (real Windows wide-string literals are) AND script-coherent.
        // Data gluing — code bytes read as pseudo-CJK, bitmap/structure
        // pairs — is neither terminated nor coherent, so it is dropped.
        let terminated = e + 2 <= bin.data.len() && bin.data[e] == 0 && bin.data[e + 1] == 0;
        if !terminated {
            return;
        }
        if !utf16_text_coherent(&text, (e - s) / 2) {
            return; // mixed-script gluing of binary data
        }
    }
    let section = bin
        .sections()
        .iter()
        .find(|sec| (sec.offset as usize) <= s && s < (sec.offset + sec.size) as usize)
        .map(|sec| sec.name.clone());
    let vaddr = bin.offset_to_vaddr(s as u64).ok();
    out.push(StrEntry {
        offset: s as u64,
        vaddr,
        len: e - s,
        text,
        section,
    });
}

pub fn hex(bin: &Binary, start: &str, len: u64, json: bool) -> Result<Out> {
    let len = len.clamp(1, 4096);
    // start: vaddr (0x...) or file offset (plain decimal or +N form)
    let (off, va) = parse_start(bin, start)?;
    let data = bin.read_at(off, len).context("read range")?;
    if json {
        let v = serde_json::json!({
            "offset": off,
            "vaddr": va,
            "len": data.len(),
            "hex": hex::encode(data),
        });
        Ok(Out::json(&v))
    } else {
        Ok(Out::text(hex_dump(data, off, va)))
    }
}

/// Resolve `start`: `0x...` = vaddr, `+N` = file offset, plain number = vaddr,
/// symbol name = symbol address.
fn parse_start(bin: &Binary, start: &str) -> Result<(u64, Option<u64>)> {
    if let Some(rest) = start.strip_prefix('+') {
        let off = u64::from_str_radix(
            rest.trim_start_matches("0x"),
            if rest.starts_with("0x") { 16 } else { 10 },
        )?;
        let va = bin.offset_to_vaddr(off).ok();
        return Ok((off, va));
    }
    let va = bin.resolve_start(start)?;
    let off = bin.vaddr_to_offset(va)?;
    Ok((off, Some(va)))
}

pub fn hash(bin: &Binary, json: bool) -> Result<Out> {
    // pure-Rust implementations: FNV-1a 64, SHA-256, MD5, SHA-1, CRC32
    let mut fnv = 0xcbf29ce484222325u64;
    for &b in &bin.data {
        fnv ^= b as u64;
        fnv = fnv.wrapping_mul(0x100000001b3);
    }
    let sha = crate::sha256::sha256(&bin.data);
    let md5 = crate::hashes::md5(&bin.data);
    let sha1 = crate::hashes::sha1(&bin.data);
    let crc = crc32(&bin.data);
    let v = serde_json::json!({
        "file": bin.path,
        "size": bin.file_size(),
        "md5": md5,
        "sha1": sha1,
        "sha256": sha,
        "crc32": format!("{crc:08x}"),
        "fnv1a64": format!("{fnv:016x}"),
    });
    if json {
        Ok(Out::json(&v))
    } else {
        Ok(Out::text(format!(
            "file:    {}\nsize:    {}\nmd5:     {}\nsha1:    {}\nsha256:  {}\ncrc32:   {crc:08x}\nfnv1a64: {fnv:016x}\n",
            bin.path,
            bin.file_size(),
            v["md5"].as_str().unwrap(),
            v["sha1"].as_str().unwrap(),
            v["sha256"].as_str().unwrap(),
        )))
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        table[i as usize] = c;
    }
    let mut crc = 0xffffffffu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffffffff
}

pub fn disasm(
    bin: &Binary,
    start: &str,
    count: usize,
    len: Option<u64>,
    until_ret: bool,
    json: bool,
) -> Result<Out> {
    let arch = bin.arch();
    if !matches!(arch, crate::core::Arch::X86 | crate::core::Arch::X64) {
        bail!(
            "disassembly is only supported for x86/x64 (got {})",
            arch.name()
        );
    }
    if count == 0 {
        bail!("count must be >= 1; --count 0 decodes nothing (use a smaller --len instead)");
    }
    let (off, va) = parse_start(bin, start)?;
    // hard cap on the decode window so a typo like --len 0xffffffff cannot
    // allocate gigabytes; 64 MiB is far beyond any real function body
    const MAX_WINDOW: u64 = 64 * 1024 * 1024;
    let max_len = match len {
        Some(l) => {
            if l > MAX_WINDOW {
                bail!(
                    "len {l:#x} exceeds the {:#x}-byte decode window; disassemble in chunks",
                    MAX_WINDOW
                );
            }
            l as usize
        }
        None => (count as u64)
            .saturating_mul(15)
            .saturating_add(16)
            .min(MAX_WINDOW) as usize,
    };
    // `--until-ret` without a ret in reach used to walk straight out of the
    // code section into file metadata (shstrtab, section headers). Clamp the
    // window to the end of the section that contains `off` so the search for
    // a ret stays inside real code.
    let max_len = if until_ret {
        if let Some(sec) = bin
            .sections()
            .iter()
            .find(|s| s.offset <= off && off < s.offset + s.size)
        {
            let sec_end = (sec.offset + sec.size) as usize;
            max_len.min(sec_end.saturating_sub(off as usize))
        } else {
            max_len
        }
    } else {
        max_len
    };
    let dec = Decoder::new(bin);
    let decoded = dec.disasm_at_offset(off, max_len);
    let mut insns: Vec<&crate::disasm::Insn> = decoded.insns.iter().collect();
    if until_ret {
        // stop at the first ret/iret at the top level: a jmp takes the flow
        // elsewhere, and a conditional jump only ends a path
        let stop_at = insns
            .iter()
            .position(|i| matches!(i.kind, "ret" | "iret"))
            .map(|p| p + 1);
        if let Some(p) = stop_at {
            insns.truncate(p);
        }
    }
    if len.is_none() && !until_ret {
        insns.truncate(count);
    }
    let stopped = decoded.stopped.clone();
    let (ch, cm, cl) = decoded.confidence_counts;
    if json {
        // Serialize instructions straight into one string instead of building
        // a Vec<serde_json::Value> first: on a full-section decode (hundreds
        // of thousands of instructions now that the sweep resyncs instead of
        // stopping) the intermediate Value tree alone tripled the peak RSS.
        // The output is valid JSON either way; MCP/CLI consumers unchanged.
        use std::fmt::Write as _;
        let mut buf = String::with_capacity(64 * 1024);
        let _ = write!(
            buf,
            "{{\n  \"start\": \"{:#x}\",\n  \"count\": {},\n  \"stopped\": ",
            va.unwrap_or(off),
            insns.len()
        );
        match &stopped {
            Some(s) => {
                let _ = write!(buf, "\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
            }
            None => buf.push_str("null"),
        }
        buf.push_str(",\n  \"insns\": [");
        for (n, i) in insns.iter().enumerate() {
            if n > 0 {
                buf.push(',');
            }
            let _ = write!(
                buf,
                "\n    {{\"addr\": \"{:#x}\", \"offset\": \"{:#x}\", \"len\": {}, \"bytes\": \"{}\", \"mnemonic\": \"{}\", \"operands\": \"{}\", \"target\": {}, \"target_symbol\": {}, \"kind\": \"{}\", \"confidence\": \"{}\"}}",
                i.addr,
                i.offset,
                i.len,
                hex::encode(&i.bytes),
                i.mnemonic,
                i.operands,
                i.target.map(|t| format!("\"{t:#x}\"")).unwrap_or_else(|| "null".into()),
                i.target_symbol
                    .as_deref()
                    .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                    .unwrap_or_else(|| "null".into()),
                i.kind,
                i.confidence,
            );
        }
        let _ = write!(
            buf,
            "\n  ],\n  \"confidence_summary\": {{\"high\": {}, \"medium\": {}, \"low\": {}}}\n}}",
            ch, cm, cl
        );
        Ok(Out::raw_json(buf))
    } else {
        let mut s = String::new();
        for i in insns {
            let bytes_hex = i
                .bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("");
            let mut line = format!(
                "{:>10}: {:24} {:8} {}",
                format!("{:#x}", i.addr),
                bytes_hex,
                i.mnemonic,
                i.operands
            );
            if let Some(sym) = &i.target_symbol {
                line.push_str(&format!("  {sym}"));
            }
            s.push_str(&line);
            s.push('\n');
        }
        Ok(Out::text(s))
    }
}

/// Entropy of a byte range (by vaddr or offset). With `window`, emit a
/// per-window entropy profile of the whole file instead (packed/encrypted
/// region detector at a glance).
pub fn entropy(
    bin: &Binary,
    start: &str,
    len: u64,
    window: Option<u64>,
    json: bool,
) -> Result<Out> {
    let (off, va) = parse_start(bin, start)?;
    if len == 0 {
        bail!("--len must be >= 1");
    }
    let len = len.clamp(1, 1 << 20);
    if let Some(win) = window {
        if win == 0 {
            bail!("--window must be >= 1");
        }
        let data = bin.read_at(off, len)?;
        let win = (win as usize).min(data.len()).max(1);
        let mut profile = Vec::new();
        let mut peak_off = 0u64;
        let mut peak_h = -1.0f64;
        for (idx, chunk) in data.chunks(win).enumerate() {
            let h = shannon_entropy(chunk);
            if h > peak_h {
                peak_h = h;
                peak_off = off + (idx * win) as u64;
            }
            profile.push(serde_json::json!({
                "offset": format!("{:#x}", off + (idx * win) as u64),
                "len": chunk.len(),
                "entropy": format!("{h:.4}"),
            }));
        }
        let mean = profile
            .iter()
            .filter_map(|p| p["entropy"].as_str().and_then(|s| s.parse::<f64>().ok()))
            .sum::<f64>()
            / profile.len().max(1) as f64;
        let v = serde_json::json!({
            "offset": format!("{off:#x}"),
            "len": len,
            "window": win,
            "windows": profile.len(),
            "mean_entropy": format!("{mean:.4}"),
            "peak_entropy": format!("{peak_h:.4}"),
            "peak_at": format!("{peak_off:#x}"),
            "profile": profile,
        });
        if json {
            Ok(Out::json(&v))
        } else {
            // inline bar chart: each window becomes one line
            let mut s = String::new();
            s.push_str(&format!(
                "entropy profile: {off:#x}..{:#x}, window {win:#x} ({} windows)\n",
                off + len,
                profile.len()
            ));
            s.push_str(&format!(
                "mean {mean:.4}, peak {peak_h:.4} at {peak_off:#x}\n"
            ));
            for p in &profile {
                let h: f64 = p["entropy"].as_str().unwrap().parse().unwrap();
                let bar_len = (h * 40.0 / 8.0).round() as usize;
                s.push_str(&format!(
                    "{} {:>7} {}\n",
                    p["offset"].as_str().unwrap(),
                    p["entropy"].as_str().unwrap(),
                    "#".repeat(bar_len)
                ));
            }
            Ok(Out::text(s))
        }
    } else {
        let data = bin.read_at(off, len)?;
        let e = shannon_entropy(data);
        let v = serde_json::json!({
            "offset": format!("{off:#x}"),
            "vaddr": va.map(|v| format!("{v:#x}")),
            "len": len,
            "entropy": format!("{e:.4}"),
            "note": if e > 7.2 { "very high - likely compressed/encrypted" } else if e > 6.5 { "high" } else { "normal" },
        });
        if json {
            Ok(Out::json(&v))
        } else {
            Ok(Out::text(format!(
                "range:  {off:#x}..{:#x}\nentropy: {e:.4} ({})\n",
                off + len,
                v["note"].as_str().unwrap()
            )))
        }
    }
}
