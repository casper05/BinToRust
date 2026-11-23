//! Output helpers: every command can emit JSON (`--json`) or human text.

use anyhow::Result;
use serde::Serialize;

pub enum Out {
    Json(serde_json::Value),
    Text(String),
    /// A pre-serialized JSON document, printed verbatim in both modes.
    /// Used by commands whose result can be huge (e.g. disasm of a whole
    /// section): building a `serde_json::Value` tree for it would triple the
    /// peak memory, so the command streams the JSON into a String instead.
    RawJson(String),
}

impl Out {
    pub fn json<V: Serialize>(v: &V) -> Out {
        Out::Json(serde_json::to_value(v).expect("serialize"))
    }

    pub fn text(s: impl Into<String>) -> Out {
        Out::Text(s.into())
    }

    pub fn raw_json(s: impl Into<String>) -> Out {
        Out::RawJson(s.into())
    }

    /// Render according to the requested format.
    pub fn print(&self, json: bool) -> Result<()> {
        match self {
            Out::Json(v) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(v)?);
                } else {
                    // pretty-print as indented JSON even in text mode for
                    // structured results; commands with real text renderings
                    // call Out::text instead.
                    println!("{}", serde_json::to_string_pretty(v)?);
                }
            }
            Out::Text(s) => {
                if json {
                    // wrap plain text in a JSON envelope
                    let v = serde_json::json!({ "text": s });
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    print!("{s}");
                }
            }
            Out::RawJson(s) => {
                // already valid JSON; print as-is (compact) in json mode and
                // pretty-printed in text mode for human skimming
                if json {
                    println!("{s}");
                } else {
                    let v: serde_json::Value = serde_json::from_str(s)?;
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
            }
        }
        Ok(())
    }
}

/// Simple table renderer for text mode.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: &[&str]) -> Table {
        Table {
            headers: headers.iter().map(|s| s.to_string()).collect(),
            rows: vec![],
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    pub fn render(&self) -> String {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();
        for r in &self.rows {
            for (i, c) in r.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(c.len());
                }
            }
        }
        let mut out = String::new();
        let line: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
            .collect();
        out.push_str(&line.join("  "));
        out.push('\n');
        out.push_str(
            &widths
                .iter()
                .map(|w| "-".repeat(*w))
                .collect::<Vec<_>>()
                .join("  "),
        );
        out.push('\n');
        for r in &self.rows {
            let cells: Vec<String> = r
                .iter()
                .enumerate()
                .map(|(i, c)| format!("{:<width$}", c, width = widths.get(i).copied().unwrap_or(0)))
                .collect();
            out.push_str(&cells.join("  "));
            out.push('\n');
        }
        out
    }
}

pub fn hex_dump(data: &[u8], base_off: u64, base_va: Option<u64>) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let off = base_off + (i * 16) as u64;
        let hex_part: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        // pad hex to 16 cells
        let mut hp = hex_part.join(" ");
        for _ in chunk.len()..16 {
            hp.push_str("   ");
        }
        match base_va {
            Some(va) => out.push_str(&format!(
                "{:#018x} ({:#018x})  {}  |{}|\n",
                off,
                va + (i * 16) as u64,
                hp,
                ascii
            )),
            None => out.push_str(&format!("{:#018x}  {}  |{}|\n", off, hp, ascii)),
        }
    }
    out
}
