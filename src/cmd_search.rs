//! Search commands: byte-pattern search with wildcards and xrefs.
//!
//! `search` finds byte patterns (`\xNN` escapes, ASCII, `??`/`..` wildcards)
//! across the whole file; `xrefs` scans executable sections for direct
//! call/jmp/jcc targets and RIP-relative data references to a given address
//! or symbol (find-code-that-uses for a binary without sources).

use crate::core::Binary;
use crate::disasm::Decoder;
use crate::out::{Out, Table};
use anyhow::{bail, Result};
use serde::Serialize;

/// Parse a pattern: hex escapes `\xNN`, ASCII chars, wildcards `??` or `..`.
pub fn parse_pattern(spec: &str) -> Result<Vec<Option<u8>>> {
    let mut out: Vec<Option<u8>> = Vec::new();
    let chars: Vec<char> = spec.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            // a full escape needs \, x, and two hex digits
            if chars.len() < i + 4 {
                bail!("dangling escape at end of pattern");
            }
            if chars[i + 1] != 'x' {
                bail!("unsupported escape \\{} (only \\xNN)", chars[i + 1]);
            }
            let h: String = chars[i + 2..i + 4].iter().collect();
            let v =
                u8::from_str_radix(&h, 16).map_err(|_| anyhow::anyhow!("bad hex escape \\x{h}"))?;
            out.push(Some(v));
            i += 4;
        } else if (c == '?' && chars.get(i + 1) == Some(&'?'))
            || (c == '.' && chars.get(i + 1) == Some(&'.'))
        {
            // '??' and '..' are both wildcard bytes
            out.push(None);
            i += 2;
        } else if c.is_ascii() {
            out.push(Some(c as u8));
            i += 1;
        } else {
            bail!("non-ascii char in pattern: {c:?}");
        }
    }
    if out.is_empty() {
        bail!("empty pattern");
    }
    if out.len() > 1 << 20 {
        bail!("pattern too long (max 1 MiB)");
    }
    Ok(out)
}

#[derive(Serialize)]
struct SearchHit {
    offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    vaddr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
    context: String,
    /// human-readable preview: matched bytes as printable ASCII
    match_bytes: String,
}

/// Anchored scan: the last non-wildcard pattern byte is the anchor. Positions
/// where `data[p] != anchor` cannot match, so the window starting at `p - L`
/// is verified only when the anchor byte agrees. Correct with wildcards and
/// O(n*m/256) on average — fast enough for multi-megabyte sections.
fn find_all(data: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
    let mut hits = Vec::new();
    let m = pat.len();
    if m == 0 || m > data.len() {
        return hits;
    }
    let anchor_idx = match (0..m).rev().find(|&i| pat[i].is_some()) {
        Some(l) => l,
        None => return (0..=data.len() - m).collect(), // all-wildcard: every position
    };
    let anchor = pat[anchor_idx].unwrap();
    let first_possible = anchor_idx;
    let mut p = first_possible;
    while p < data.len() {
        if data[p] == anchor {
            let i = p - anchor_idx;
            if i + m <= data.len() {
                let mut ok = true;
                for j in 0..m {
                    if let Some(v) = pat[j] {
                        if data[i + j] != v {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    hits.push(i);
                }
            }
        }
        p += 1;
    }
    hits
}

pub fn search(bin: &Binary, pattern: &str, max_hits: usize, json: bool) -> Result<Out> {
    let pat = parse_pattern(pattern)?;
    if max_hits == 0 {
        bail!("--max must be >= 1");
    }
    let data = &bin.data;
    let offsets = find_all(data, &pat);
    let total = offsets.len();
    let shown = offsets.into_iter().take(max_hits);
    let mut hits = Vec::new();
    for off in shown {
        let ctx_start = off.saturating_sub(8);
        let ctx_end = (off + pat.len() + 8).min(data.len());
        let context = data[ctx_start..ctx_end]
            .iter()
            .map(|&b| {
                if b == 0x09 || (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        let matched = data[off..off + pat.len()]
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect::<String>();
        hits.push(SearchHit {
            offset: off as u64,
            vaddr: bin
                .offset_to_vaddr(off as u64)
                .ok()
                .map(|v| format!("{v:#x}")),
            section: bin
                .sections()
                .iter()
                .find(|s| (s.offset as usize) <= off && off < (s.offset + s.size) as usize)
                .map(|s| s.name.clone()),
            context,
            match_bytes: matched,
        });
    }
    let v = serde_json::json!({
        "pattern": pattern,
        "pattern_len": pat.len(),
        "matches": total,
        "shown": hits.len(),
        "truncated": total > hits.len(),
        "hits": hits,
    });
    if json {
        Ok(Out::json(&v))
    } else {
        let mut s = String::new();
        s.push_str(&format!(
            "pattern: {pattern} ({} bytes)\nmatches: {total}\n",
            pat.len()
        ));
        if total > hits.len() {
            s.push_str(&format!("(showing first {})\n", hits.len()));
        }
        for h in &hits {
            let va = h
                .vaddr
                .as_deref()
                .map(|v| format!(" va {v}"))
                .unwrap_or_default();
            s.push_str(&format!("  +{:#x}{va}  [{}]\n", h.offset, h.match_bytes));
        }
        Ok(Out::text(s))
    }
}

// ---------------- xrefs ----------------

#[derive(Serialize)]
struct Xref {
    from_addr: String,
    from_offset: String,
    kind: String, // call | jmp | jcc | data
    insn: String, // mnemonic + operands
    /// symbol containing the referencing instruction
    #[serde(skip_serializing_if = "Option::is_none")]
    from_symbol: Option<String>,
}

/// Find references to `target` (vaddr or symbol name) across code sections:
/// direct call/jmp/jcc targets and RIP-relative data accesses.
pub fn xrefs(bin: &Binary, target_spec: &str, json: bool) -> Result<Out> {
    let arch = bin.arch();
    if !matches!(arch, crate::core::Arch::X86 | crate::core::Arch::X64) {
        bail!(
            "xrefs need disassembly, which is only supported for x86/x64 (got {})",
            arch.name()
        );
    }
    let target: u64 = bin.resolve_start(target_spec)?;
    let dec = Decoder::new(bin);
    let mut refs: Vec<Xref> = Vec::new();
    let mut sections_scanned = 0usize;
    // coverage: bytes the linear sweep could not scan (a non-`truncated`
    // stop). Resyncs on data islands no longer stop the sweep, so this is
    // normally 0; anything above means the agent should treat the result
    // as a lower bound.
    let mut unscanned_bytes: usize = 0;
    let mut scan_notes: Vec<String> = Vec::new();
    for sec in bin.sections().iter().filter(|s| s.kind == "code") {
        sections_scanned += 1;
        let start = sec.offset as usize;
        let end = start.saturating_add(sec.size as usize).min(bin.data.len());
        if start >= end {
            continue;
        }
        let decoded = dec.disasm_at_offset(sec.offset, (end - start) as u64 as usize);
        if let Some(reason) = &decoded.stopped {
            unscanned_bytes += (end - start).saturating_sub(decoded.consumed);
            scan_notes.push(format!(
                "{}: stopped at {:#x} ({reason})",
                sec.name,
                sec.offset as usize + decoded.consumed
            ));
        }
        for insn in decoded.insns {
            let kind = if insn.target == Some(target) && matches!(insn.kind, "call" | "jmp" | "jcc")
            {
                insn.kind
            } else if insn.rip_target == Some(target) {
                "data"
            } else {
                continue;
            };
            refs.push(Xref {
                from_addr: format!("{:#x}", insn.addr),
                from_offset: format!("{:#x}", insn.offset),
                kind: kind.to_string(),
                insn: format!("{} {}", insn.mnemonic, insn.operands),
                from_symbol: dec.symbol_at(insn.addr).map(|(n, d)| {
                    if d == 0 {
                        n.to_string()
                    } else {
                        format!("{n}+{d:#x}")
                    }
                }),
            });
        }
    }
    let (calls, jumps, data) = (
        refs.iter().filter(|r| r.kind == "call").count(),
        refs.iter()
            .filter(|r| r.kind == "jmp" || r.kind == "jcc")
            .count(),
        refs.iter().filter(|r| r.kind == "data").count(),
    );
    let v = serde_json::json!({
        "target": format!("{target:#x}"),
        "target_spec": target_spec,
        "target_symbol": dec.symbol_at(target).map(|(n, d)| if d == 0 { n.to_string() } else { format!("{n}+{d:#x}") }),
        "sections_scanned": sections_scanned,
        "unscanned_bytes": unscanned_bytes,
        "scan_notes": scan_notes,
        "xrefs_total": refs.len(),
        "by_kind": { "call": calls, "jmp/jcc": jumps, "data": data },
        "xrefs": refs,
    });
    if json {
        Ok(Out::json(&v))
    } else {
        let mut t = Table::new(&["from", "kind", "in function", "instruction"]);
        for r in v["xrefs"].as_array().unwrap() {
            t.row(vec![
                r["from_addr"].as_str().unwrap().to_string(),
                r["kind"].as_str().unwrap().to_string(),
                r["from_symbol"].as_str().unwrap_or("-").to_string(),
                r["insn"].as_str().unwrap().to_string(),
            ]);
        }
        let mut s = String::new();
        s.push_str(&format!(
            "xrefs to {target:#x}{} ({} code sections)\n",
            v["target_symbol"]
                .as_str()
                .map(|s| format!(" {s}"))
                .unwrap_or_default(),
            sections_scanned
        ));
        s.push_str(&format!(
            "total: {} (call {}, jmp/jcc {}, data {})\n",
            refs.len(),
            calls,
            jumps,
            data
        ));
        if unscanned_bytes > 0 {
            s.push_str(&format!(
                "warning: {unscanned_bytes} bytes not scanned; result is a lower bound\n"
            ));
            for n in &scan_notes {
                s.push_str(&format!("  {n}\n"));
            }
        }
        s.push_str(&t.render());
        Ok(Out::text(s))
    }
}
