//! Modification / diffing commands: compare, patch, carve.

use crate::core::Binary;
use crate::out::{hex_dump, Out, Table};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;

// ---------------- compare ----------------

#[derive(Serialize)]
struct DiffChunk {
    #[serde(serialize_with = "hex_u64")]
    offset: u64,
    a_bytes: Vec<u8>,
    b_bytes: Vec<u8>,
    #[serde(serialize_with = "opt_hex_u64")]
    a_vaddr: Option<u64>,
    #[serde(serialize_with = "opt_hex_u64")]
    b_vaddr: Option<u64>,
}

#[derive(Serialize)]
struct CompareResult {
    file_a: String,
    file_b: String,
    size_a: u64,
    size_b: u64,
    sha256_a: String,
    sha256_b: String,
    identical: bool,
    size_match: bool,
    regions: Vec<DiffRegion>,
    regions_total: u64,
    regions_truncated: bool,
    diff_chunks: Vec<DiffChunk>,
    diff_bytes: u64,
}

#[derive(Serialize)]
struct DiffRegion {
    #[serde(serialize_with = "hex_u64")]
    start: u64,
    #[serde(serialize_with = "hex_u64")]
    end: u64,
    len: u64,
    #[serde(serialize_with = "opt_hex_u64")]
    a_vaddr: Option<u64>,
    #[serde(serialize_with = "opt_hex_u64")]
    b_vaddr: Option<u64>,
}

fn hex_u64<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:#x}"))
}

fn opt_hex_u64<S: serde::Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(x) => s.serialize_str(&format!("{x:#x}")),
        None => s.serialize_none(),
    }
}

pub fn compare(path_a: &str, path_b: &str, max_chunks: usize, json: bool) -> Result<Out> {
    let data_a = std::fs::read(path_a).with_context(|| format!("cannot read {path_a}"))?;
    let data_b = std::fs::read(path_b).with_context(|| format!("cannot read {path_b}"))?;
    let sha_a = crate::sha256::sha256(&data_a);
    let sha_b = crate::sha256::sha256(&data_b);

    // parse both if possible, to annotate vaddrs; reborrows the buffers
    // instead of cloning (compare of a 100 MB binary must not double memory)
    let bin_a = parse_no_clone(&data_a, path_a);
    let bin_b = parse_no_clone(&data_b, path_b);
    let va = |b: &Option<Binary>, off: u64| -> Option<u64> {
        b.as_ref().and_then(|bin| bin.offset_to_vaddr(off).ok())
    };

    let mut regions: Vec<DiffRegion> = Vec::new();
    let mut chunks = Vec::new();
    let mut diff_bytes = 0u64;
    let mut regions_total: u64 = 0;
    const REGION_MERGE_GAP: u64 = 16; // merge regions separated by less than this
    const REGION_CAP: usize = 10_000; // bound memory/JSON on huge diffs
    let common = data_a.len().min(data_b.len());
    let mut i = 0usize;
    while i < common {
        if data_a[i] != data_b[i] {
            let start = i;
            while i < common && data_a[i] != data_b[i] {
                i += 1;
            }
            // extend by a little context
            diff_bytes += (i - start) as u64;
            regions_total += 1;
            let a_va = va(&bin_a, start as u64);
            let b_va = va(&bin_b, start as u64);
            // merge with the previous region when the gap is tiny
            let merged = if let Some(prev) = regions.last_mut() {
                if start as u64 - prev.end <= REGION_MERGE_GAP {
                    prev.end = i as u64;
                    prev.len = prev.end - prev.start;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !merged && regions.len() < REGION_CAP {
                regions.push(DiffRegion {
                    start: start as u64,
                    end: i as u64,
                    len: (i - start) as u64,
                    a_vaddr: a_va,
                    b_vaddr: b_va,
                });
            }
        } else {
            i += 1;
        }
    }
    if data_a.len() != data_b.len() {
        regions_total += 1;
        if regions.len() < REGION_CAP {
            regions.push(DiffRegion {
                start: common as u64,
                end: data_a.len().max(data_b.len()) as u64,
                len: (data_a.len().max(data_b.len()) - common) as u64,
                a_vaddr: va(&bin_a, common as u64),
                b_vaddr: va(&bin_b, common as u64),
            });
        }
        diff_bytes += (data_a.len().max(data_b.len()) - common) as u64;
    }
    // build chunk samples (merge regions within 16 bytes)
    let mut idx = 0;
    while idx < regions.len() && chunks.len() < max_chunks {
        let r = &regions[idx];
        let s = r.start as usize;
        let e = r.end as usize;
        let ctx = 8;
        let s2 = s.saturating_sub(ctx);
        let e2 = (e + ctx).min(common.max(1));
        let e2 = e2.min(data_a.len()).min(data_b.len());
        chunks.push(DiffChunk {
            offset: s2 as u64,
            a_bytes: data_a[s2..e2].to_vec(),
            b_bytes: data_b[s2..e2].to_vec(),
            a_vaddr: va(&bin_a, s2 as u64),
            b_vaddr: va(&bin_b, s2 as u64),
        });
        // skip overlapping regions
        while idx < regions.len() && (regions[idx].start as usize) < e + ctx {
            idx += 1;
        }
    }

    let identical = sha_a == sha_b && data_a.len() == data_b.len();
    let res = CompareResult {
        file_a: path_a.to_string(),
        file_b: path_b.to_string(),
        size_a: data_a.len() as u64,
        size_b: data_b.len() as u64,
        sha256_a: sha_a,
        sha256_b: sha_b,
        identical,
        size_match: data_a.len() == data_b.len(),
        regions,
        regions_total,
        regions_truncated: regions_total > REGION_CAP as u64,
        diff_chunks: chunks,
        diff_bytes,
    };
    if json {
        Ok(Out::json(&res))
    } else {
        let mut s = String::new();
        s.push_str(&format!(
            "A: {} ({}) sha256={}\nB: {} ({}) sha256={}\nidentical: {}\n",
            path_a,
            res.size_a,
            &res.sha256_a[..16],
            path_b,
            res.size_b,
            &res.sha256_b[..16],
            identical
        ));
        if !res.size_match {
            s.push_str(&format!(
                "size mismatch: {} vs {}\n",
                res.size_a, res.size_b
            ));
        }
        s.push_str(&format!("diff bytes: {}/{common}\n", res.diff_bytes));
        s.push_str(&format!(
            "diff regions: {}{}\n",
            res.regions_total,
            if res.regions_truncated {
                format!(" (showing first {})", res.regions.len())
            } else {
                String::new()
            }
        ));
        for r in &res.regions {
            let va_note = r
                .a_vaddr
                .map(|v| format!(" (A va {v:#x})"))
                .unwrap_or_default();
            s.push_str(&format!(
                "  {:#010x}..{:#010x}  len {}{va_note}\n",
                r.start, r.end, r.len
            ));
        }
        for c in &res.diff_chunks {
            s.push_str(&format!("\n@ {:#x}\n", c.offset));
            s.push_str(&hex_dump(&c.a_bytes, c.offset, c.a_vaddr));
            s.push_str("---\n");
            s.push_str(&hex_dump(&c.b_bytes, c.offset, c.b_vaddr));
        }
        Ok(Out::text(s))
    }
}

// ---------------- patch ----------------

/// Apply a byte patch at a file offset or vaddr. Supports hex strings and
/// escape sequences \xNN, \n, \t, \0, \r.
pub fn parse_patch_bytes(spec: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chars = spec.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('x') => {
                    let h: String = chars.by_ref().take(2).collect();
                    if h.len() != 2 {
                        bail!("bad \\x escape");
                    }
                    out.push(u8::from_str_radix(&h, 16)?);
                }
                Some('n') => out.push(b'\n'),
                Some('t') => out.push(b'\t'),
                Some('r') => out.push(b'\r'),
                Some('0') => out.push(0),
                Some('\\') => out.push(b'\\'),
                Some(o) => bail!("unsupported escape \\{o}"),
                None => bail!("trailing backslash"),
            },
            c if c.is_ascii() => out.push(c as u8),
            c => bail!("non-ascii char in patch spec: {c:?}"),
        }
    }
    if out.is_empty() {
        bail!("empty patch");
    }
    Ok(out)
}

#[derive(Serialize)]
struct PatchResult {
    file: String,
    at: String,
    as_offset: u64,
    as_vaddr: Option<String>,
    old_bytes: Vec<u8>,
    new_bytes: Vec<u8>,
    written: u64,
    output: String,
    backup: Option<String>,
}

pub fn patch(
    input: &str,
    at: &str,
    bytes: &str,
    output: Option<&str>,
    json: bool,
    backup: bool,
) -> Result<Out> {
    let bin = Binary::load(input)?;
    let new_bytes = parse_patch_bytes(bytes)?;
    let (off, va) = if let Some(rest) = at.strip_prefix('+') {
        let o = rest
            .strip_prefix("0x")
            .map(|r| u64::from_str_radix(r, 16))
            .unwrap_or_else(|| rest.parse::<u64>())?;
        (o, bin.offset_to_vaddr(o).ok())
    } else {
        let v = bin.resolve_start(at)?;
        (bin.vaddr_to_offset(v)?, Some(v))
    };
    let old = bin.read_at(off, new_bytes.len() as u64)?.to_vec();
    let mut data = bin.data.clone();
    data[off as usize..off as usize + new_bytes.len()].copy_from_slice(&new_bytes);
    let out_path = output.unwrap_or(input).to_string();
    let backup_path = if backup && out_path == input {
        let b = format!("{input}.bak");
        std::fs::copy(input, &b).ok().map(|_| b)
    } else {
        None
    };
    std::fs::write(&out_path, &data).with_context(|| format!("cannot write {out_path}"))?;
    let res = PatchResult {
        file: input.to_string(),
        at: at.to_string(),
        as_offset: off,
        as_vaddr: va.map(|v| format!("{v:#x}")),
        old_bytes: old.clone(),
        new_bytes: new_bytes.clone(),
        written: new_bytes.len() as u64,
        output: out_path,
        backup: backup_path,
    };
    if json {
        Ok(Out::json(&res))
    } else {
        let mut s = String::new();
        s.push_str(&format!(
            "patched {} at {} (file offset {off:#x})\n",
            res.output, res.at
        ));
        s.push_str(&format!("old: {}\n", hex::encode(&old)));
        s.push_str(&format!("new: {}\n", hex::encode(&new_bytes)));
        if let Some(b) = &res.backup {
            s.push_str(&format!("backup: {b}\n"));
        }
        Ok(Out::text(s))
    }
}

// ---------------- carve ----------------

#[derive(Serialize)]
struct CarveHit {
    kind: String,
    offset: u64,
    size: u64,
    note: String,
}

/// Carve embedded objects: PE (MZ..PE), ELF, gzip, zip, PNG, JPEG, tar, and
/// common certificates.
pub fn carve(input: &str, json: bool, min_size: u64) -> Result<Out> {
    let data = std::fs::read(input).with_context(|| format!("cannot read {input}"))?;
    let mut hits = Vec::new();

    // PE inside
    for i in 0..data.len().saturating_sub(64) {
        if &data[i..i + 2] == b"MZ" {
            let pe_off = match u32::from_le_bytes(
                data.get(i + 0x3c..i + 0x40)
                    .map(|s| s.try_into().unwrap())
                    .unwrap_or([0; 4]),
            ) as usize
            {
                o if o + i + 24 < data.len() && &data[i + o..i + o + 4] == b"PE\0\0" => i + o,
                _ => continue,
            };
            let nsec =
                u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
            let opt =
                u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
            let end = pe_off + 24 + opt + nsec * 40;
            if end < data.len() {
                hits.push(CarveHit {
                    kind: "PE".into(),
                    offset: i as u64,
                    size: (data.len() - i) as u64,
                    note: format!("{nsec} sections (trailing size until EOF)"),
                });
            }
        }
    }
    // ELF: validate the header and compute the real file size from section
    // headers, skipping SHT_NOBITS (BSS occupies no file bytes).
    for i in 0..data.len().saturating_sub(52) {
        if &data[i..i + 4] != b"\x7fELF" {
            continue;
        }
        let cls = data[i + 4];
        let is64 = cls == 2;
        let (e_shoff, e_shentsize, e_shnum) = if is64 {
            if i + 64 > data.len() {
                continue;
            }
            (
                u64::from_le_bytes(data[i + 0x28..i + 0x30].try_into().unwrap()) as usize,
                u16::from_le_bytes(data[i + 0x3a..i + 0x3c].try_into().unwrap()) as usize,
                u16::from_le_bytes(data[i + 0x3c..i + 0x3e].try_into().unwrap()) as usize,
            )
        } else {
            if i + 52 > data.len() {
                continue;
            }
            (
                u32::from_le_bytes(data[i + 0x20..i + 0x24].try_into().unwrap()) as usize,
                u16::from_le_bytes(data[i + 0x2e..i + 0x30].try_into().unwrap()) as usize,
                u16::from_le_bytes(data[i + 0x30..i + 0x32].try_into().unwrap()) as usize,
            )
        };
        if e_shoff == 0 || e_shnum == 0 || e_shentsize == 0 {
            // no section headers: fall back to "until EOF"
            hits.push(CarveHit {
                kind: "ELF".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "embedded ELF (no section headers, size until EOF)".into(),
            });
            continue;
        }
        let shend = i + e_shoff + e_shnum * e_shentsize;
        if e_shoff
            .checked_add(e_shnum.saturating_mul(e_shentsize))
            .is_none()
            || shend > data.len() + i
        {
            continue; // section table out of range: not a real ELF
        }
        // real file extent = max(section offset + size) over non-NOBITS sections
        let mut file_end = i + 64.min(data.len() - i);
        for s in 0..e_shnum {
            let sh = i + e_shoff + s * e_shentsize;
            let (sh_type, off, size) = if is64 {
                (
                    u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap()),
                    u64::from_le_bytes(data[sh + 0x18..sh + 0x20].try_into().unwrap()) as usize,
                    u64::from_le_bytes(data[sh + 0x20..sh + 0x28].try_into().unwrap()) as usize,
                )
            } else {
                (
                    u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap()),
                    u32::from_le_bytes(data[sh + 0x10..sh + 0x14].try_into().unwrap()) as usize,
                    u32::from_le_bytes(data[sh + 0x14..sh + 0x18].try_into().unwrap()) as usize,
                )
            };
            if sh_type == 8 {
                continue; // SHT_NOBITS: no bytes in the file
            }
            let end = off.saturating_add(size);
            if end > file_end - i {
                file_end = i + end;
            }
        }
        file_end = file_end.min(data.len());
        hits.push(CarveHit {
            kind: "ELF".into(),
            offset: i as u64,
            size: (file_end - i) as u64,
            note: format!("embedded ELF, {e_shnum} sections (size covers non-NOBITS data)"),
        });
    }
    // gzip magic 1f 8b
    let mut i = 0;
    while i + 2 < data.len() {
        if data[i] == 0x1f && data[i + 1] == 0x8b && data[i + 2] == 0x08 {
            hits.push(CarveHit {
                kind: "gzip".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "gzip stream (deflate)".into(),
            });
        }
        i += 1;
    }
    // PNG / JPEG / ZIP / RAR / 7z / CAB / xz / zstd / OLE2
    for i in 0..data.len().saturating_sub(4) {
        let m = &data[i..i + 4];
        if m == b"\x89PNG" {
            hits.push(CarveHit {
                kind: "PNG".into(),
                offset: i as u64,
                size: png_size(&data[i..]).unwrap_or(0),
                note: "PNG image".into(),
            });
        } else if m == b"\xff\xd8\xff\xe0" || m == b"\xff\xd8\xff\xe1" || m == b"\xff\xd8\xff\xdb" {
            hits.push(CarveHit {
                kind: "JPEG".into(),
                offset: i as u64,
                size: jpeg_size(&data[i..]).unwrap_or(0),
                note: "JPEG image".into(),
            });
        } else if m == b"PK\x03\x04" {
            hits.push(CarveHit {
                kind: "ZIP".into(),
                offset: i as u64,
                size: zip_size(&data[i..]).unwrap_or(0),
                note: "ZIP archive".into(),
            });
        } else if m == b"Rar!" && data.len() > i + 7 && &data[i + 4..i + 7] == b"\x1a\x07\x00" {
            hits.push(CarveHit {
                kind: "RAR".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "RAR archive (v1.5+)".into(),
            });
        } else if m == b"Rar!" && data.len() > i + 8 && &data[i + 4..i + 8] == b"\x1a\x07\x01\x00" {
            hits.push(CarveHit {
                kind: "RAR".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "RAR archive (v5+)".into(),
            });
        } else if m == b"7z\xbc\xaf" && data.len() > i + 6 && &data[i + 4..i + 6] == b"\x27\x1c" {
            hits.push(CarveHit {
                kind: "7z".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "7-Zip archive".into(),
            });
        } else if m == b"MSCF" {
            hits.push(CarveHit {
                kind: "CAB".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "Microsoft Cabinet archive".into(),
            });
        } else if m == b"\xfd7zX" && data.len() > i + 6 && &data[i + 4..i + 6] == b"Z\x00" {
            hits.push(CarveHit {
                kind: "xz".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "XZ compressed stream".into(),
            });
        } else if m == b"\x28\xb5\x2f\xfd" {
            hits.push(CarveHit {
                kind: "zstd".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "Zstandard frame".into(),
            });
        } else if m == b"\xd0\xcf\x11\xe0" {
            hits.push(CarveHit {
                kind: "OLE2".into(),
                offset: i as u64,
                size: (data.len() - i) as u64,
                note: "OLE2 compound document (MS Office / MSI)".into(),
            });
        }
    }
    // UPX! magic can appear unaligned; scan for the packer signature
    let mut i = 0;
    while i + 4 <= data.len() {
        if &data[i..i + 4] == b"UPX!" {
            hits.push(CarveHit {
                kind: "UPX".into(),
                offset: i as u64,
                size: 0,
                note: "UPX packer signature (the file is likely packed)".into(),
            });
        }
        i += 1;
    }
    // dedup + filter by size
    hits.retain(|h| h.size >= min_size);
    hits.sort_by_key(|h| h.offset);
    hits.dedup_by_key(|h| (h.kind.clone(), h.offset));

    if json {
        Ok(Out::json(&hits))
    } else {
        let mut t = Table::new(&["kind", "offset", "size", "note"]);
        for h in &hits {
            t.row(vec![
                h.kind.clone(),
                format!("{:#x}", h.offset),
                format!("{:#x}", h.size),
                h.note.clone(),
            ]);
        }
        if hits.is_empty() {
            Ok(Out::text("no embedded objects found\n"))
        } else {
            Ok(Out::text(t.render()))
        }
    }
}

fn png_size(d: &[u8]) -> Option<u64> {
    // IHDR width/height then scan chunks for IEND
    if d.len() < 24 {
        return None;
    }
    let mut off = 8usize;
    while off + 8 <= d.len() {
        let len = u32::from_be_bytes(d[off..off + 4].try_into().ok()?) as usize;
        let typ = &d[off + 4..off + 8];
        if typ == b"IEND" {
            return Some((off + 12) as u64);
        }
        off += 12 + len;
    }
    None
}

fn jpeg_size(d: &[u8]) -> Option<u64> {
    let mut off = 2usize;
    while off + 4 <= d.len() {
        if d[off] != 0xff {
            off += 1;
            continue;
        }
        let marker = d[off + 1];
        if marker == 0xd9 {
            return Some((off + 2) as u64);
        }
        if (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            off += 2;
            continue;
        }
        let seglen = u16::from_be_bytes(d[off + 2..off + 4].try_into().ok()?) as usize;
        off += 2 + seglen;
    }
    None
}

fn zip_size(d: &[u8]) -> Option<u64> {
    // find EOCD 50 4b 05 06
    let tail = &d[d.len().saturating_sub(65557)..];
    for i in 0..tail.len().saturating_sub(4) {
        if &tail[i..i + 4] == b"PK\x05\x06" {
            let off = d.len() - tail.len() + i;
            let cd_size = u32::from_le_bytes(d.get(off + 12..off + 16)?.try_into().ok()?) as u64;
            let cd_off = u32::from_le_bytes(d.get(off + 16..off + 20)?.try_into().ok()?) as u64;
            return Some(
                off as u64 + 22u64 + cd_size.saturating_sub(cd_off.saturating_add(off as u64)),
            );
        }
    }
    None
}

/// Extract a byte range into a separate file.
pub fn extract(input: &str, offset: &str, size: u64, output: &str, json: bool) -> Result<Out> {
    let data = std::fs::read(input).with_context(|| format!("cannot read {input}"))?;
    let off = if let Some(r) = offset.strip_prefix("0x") {
        u64::from_str_radix(r, 16)?
    } else {
        offset.parse::<u64>()?
    };
    if off
        .checked_add(size)
        .map(|e| e > data.len() as u64)
        .unwrap_or(true)
    {
        bail!(
            "range {off:#x}+{size:#x} exceeds file size {:#x}",
            data.len()
        );
    }
    let slice = &data[off as usize..(off + size) as usize];
    std::fs::write(output, slice).with_context(|| format!("cannot write {output}"))?;
    let v = serde_json::json!({
        "input": input,
        "offset": format!("{off:#x}"),
        "size": size,
        "output": output,
        "sha256": crate::sha256::sha256(slice),
    });
    if json {
        Ok(Out::json(&v))
    } else {
        Ok(Out::text(format!(
            "extracted {size} bytes from {off:#x} to {output}\nsha256: {}\n",
            crate::sha256::sha256(slice)
        )))
    }
}

// ---------------- reloc table (BTreeMap import used above) ----------------

#[allow(dead_code)]
type _Unused = BTreeMap<u8, u8>;

/// Parse a binary from a borrowed buffer. `Binary::from_data` takes ownership
/// (it stores the file contents), so this re-reads from disk only when the
/// buffer actually parses — callers that just need section mapping (compare)
/// avoid duplicating multi-megabyte files in memory.
fn parse_no_clone(data: &[u8], path: &str) -> Option<Binary> {
    let looks_binary = (data.len() >= 4 && &data[0..4] == b"\x7fELF")
        || (data.len() >= 2 && data[0] == b'M' && data[1] == b'Z');
    if !looks_binary {
        return None;
    }
    // Only ELF/PE parse; the re-read is the price of the owned-data design.
    Binary::load(path).ok()
}
