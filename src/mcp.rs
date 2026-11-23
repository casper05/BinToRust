//! MCP (Model Context Protocol) server over stdio.
//!
//! Implements JSON-RPC 2.0 with the MCP methods an agent host needs:
//! initialize / ping / tools/list / tools/call. Each tool maps 1:1 to a CLI
//! subcommand so behaviour stays identical between the two interfaces.

use crate::{cmd_analyze, cmd_mod, cmd_run, cmd_search};
use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

pub const SERVER_NAME: &str = "bin-anything";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Tool descriptor: name, description, JSON-schema-ish input.
struct Tool {
    name: &'static str,
    desc: &'static str,
    schema: Value,
}

fn s(t: &str) -> Value {
    json!({ "type": "string", "description": t })
}

fn opt_s(t: &str) -> Value {
    json!({ "type": "string", "description": t })
}

fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "inspect",
            desc: "High-level overview of a binary: format, arch, bits, entry point, image base, section/symbol/import/export counts, interpreter, security mitigations, packed-heuristic.",
            schema: json!({
                "type": "object",
                "properties": { "path": s("path to the binary file") },
                "required": ["path"]
            }),
        },
        Tool {
            name: "sections",
            desc: "List sections with virtual addresses, file offsets, sizes, flags and entropy.",
            schema: json!({
                "type": "object",
                "properties": { "path": s("path to the binary file") },
                "required": ["path"]
            }),
        },
        Tool {
            name: "symbols",
            desc: "List symbols (ELF symtab+dynsym, PE exports). Optional substring filter, kind filter (func|object|section|file|unknown) and limit.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "filter": opt_s("substring filter (case-insensitive)"),
                    "kind": opt_s("kind filter: func|object|section|file|unknown"),
                    "limit": json!({"type": "integer", "description": "show at most N symbols (with total count)"})
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "search",
            desc: "Search the whole file for a byte pattern with wildcards: \\xNN hex escapes, ASCII chars, ?? or .. for any byte. Finds opcodes, strings, constants.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "pattern": s("pattern, e.g. \\xe8\\x??\\xff\\xff\\xff or CC Strat"),
                    "max": json!({"type": "integer", "description": "maximum matches to report (default 200)"})
                },
                "required": ["path", "pattern"]
            }),
        },
        Tool {
            name: "xrefs",
            desc: "Find references to an address or symbol: direct call/jmp/jcc targets and RIP-relative data accesses, scanned over code sections.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "target": s("0xADDR or symbol name")
                },
                "required": ["path", "target"]
            }),
        },
        Tool {
            name: "imports",
            desc: "List imported functions: for ELF - undefined dynamic symbols; for PE - the import table with modules.",
            schema: json!({
                "type": "object",
                "properties": { "path": s("path to the binary file") },
                "required": ["path"]
            }),
        },
        Tool {
            name: "functions",
            desc: "List function boundaries in code sections: prologue detection (push rbp/mov rbp,rsp, endbr64) plus symbol starts, with upper-bound sizes.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "limit": s("show at most N functions")
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "resources",
            desc: "List the PE resource tree (.rsrc): types (RT_*), names, languages and data leaf offsets/sizes.",
            schema: json!({
                "type": "object",
                "properties": { "path": s("path to the PE file") },
                "required": ["path"]
            }),
        },
        Tool {
            name: "exports",
            desc: "List exported symbols (ELF dynsym defined; PE export directory).",
            schema: json!({
                "type": "object",
                "properties": { "path": s("path to the binary file") },
                "required": ["path"]
            }),
        },
        Tool {
            name: "strings",
            desc: "Extract printable strings — ASCII by default, UTF-16LE with utf16=true (Windows binaries). Optional min length, filter and limit.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "min_len": json!({"type": "integer", "description": "minimum length (default 4)"}),
                    "filter": opt_s("substring filter (case-insensitive)"),
                    "limit": json!({"type": "integer", "description": "show at most N strings (with total count)"}),
                    "utf16": json!({"type": "boolean", "description": "extract UTF-16LE strings instead of ASCII"})
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "hex",
            desc: "Hex dump a range. start accepts: 0xADDR (virtual address), +N (file offset), or a symbol name.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "start": s("0xADDR | +OFFSET | symbol"),
                    "len": json!({"type": "integer", "description": "bytes to show (default 256, max 4096)"})
                },
                "required": ["path", "start"]
            }),
        },
        Tool {
            name: "disasm",
            desc: "Disassemble x86/x64 code at a start point (address/offset/symbol). Returns instructions with bytes, mnemonics, operand sketch, branch targets and symbol annotations. until_ret stops at the first ret (whole function).",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "start": s("0xADDR | +OFFSET | symbol"),
                    "count": json!({"type": "integer", "description": "max instructions (default 40)"}),
                    "len": opt_s("alternative to count: disassemble exactly LEN bytes"),
                    "until_ret": json!({"type": "boolean", "description": "stop at the first ret/iret (decode the whole current function)"})
                },
                "required": ["path", "start"]
            }),
        },
        Tool {
            name: "hash",
            desc: "File hashes: SHA-256, CRC32, FNV-1a 64.",
            schema: json!({
                "type": "object",
                "properties": { "path": s("path to the binary file") },
                "required": ["path"]
            }),
        },
        Tool {
            name: "entropy",
            desc: "Shannon entropy of a byte range (packed/encrypted region detector). With window: per-window entropy profile of the range.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("path to the binary file"),
                    "start": s("0xADDR | +OFFSET | symbol"),
                    "len": json!({"type": "integer", "description": "bytes (default 4096)"}),
                    "window": json!({"type": "integer", "description": "emit a per-window entropy profile (packed/encrypted region finder)"})
                },
                "required": ["path", "start"]
            }),
        },
        Tool {
            name: "compare",
            desc: "Byte-level diff of two binaries: changed regions with vaddr annotations, sha256, hex chunks. Use for patch verification or version comparison.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path_a": s("first file"),
                    "path_b": s("second file")
                },
                "required": ["path_a", "path_b"]
            }),
        },
        Tool {
            name: "patch",
            desc: "Patch bytes at an address/offset/symbol into a (new) file. bytes accepts hex escapes like \\x90 or literal ASCII.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("input file"),
                    "at": s("0xADDR | +OFFSET | symbol"),
                    "bytes": s("new bytes, e.g. \\x90\\x90 or BADC"),
                    "output": opt_s("output file (default: overwrite input; use --backup)"),
                    "backup": json!({"type": "boolean", "description": "create <input>.bak before overwriting"})
                },
                "required": ["path", "at", "bytes"]
            }),
        },
        Tool {
            name: "carve",
            desc: "Find embedded objects (PE, ELF, gzip, ZIP, PNG, JPEG) inside a file.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("input file"),
                    "min_size": json!({"type": "integer", "description": "minimum embedded object size"})
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "extract",
            desc: "Extract a byte range from a file into a new file.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("input file"),
                    "offset": s("file offset, e.g. 0x400"),
                    "size": json!({"type": "integer", "description": "bytes to extract"}),
                    "output": s("output file")
                },
                "required": ["path", "offset", "size", "output"]
            }),
        },
        Tool {
            name: "run",
            desc: "Run the binary with args, capture exit code / stdout / stderr / duration. Timeout-protected.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("binary to run"),
                    "args": json!({"type": "array", "items": {"type": "string"}, "description": "command-line arguments"}),
                    "timeout_secs": json!({"type": "integer", "description": "default 10"}),
                    "env": json!({"type": "array", "items": {"type": "string"}, "description": "extra env K=V entries"})
                },
                "required": ["path"]
            }),
        },
        Tool {
            name: "record",
            desc: "Record a behavior snapshot of the binary: exit code, stdout/stderr hashes+heads, duration, files created in a watch dir. Saves JSON snapshot.",
            schema: json!({
                "type": "object",
                "properties": {
                    "path": s("binary to run"),
                    "args": json!({"type": "array", "items": {"type": "string"}}),
                    "snapshot": s("where to save the snapshot JSON"),
                    "stdin_file": opt_s("file to feed on stdin"),
                    "timeout_secs": json!({"type": "integer"}),
                    "cwd": opt_s("working directory"),
                    "env": json!({"type": "array", "items": {"type": "string"}}),
                    "watch_dir": opt_s("directory whose files are hashed before/after (detect outputs)")
                },
                "required": ["path", "snapshot"]
            }),
        },
        Tool {
            name: "replay",
            desc: "Re-run the binary from a snapshot and report which behavior fields match or differ (exit code, stdout/stderr hashes, files).",
            schema: json!({
                "type": "object",
                "properties": {
                    "snapshot": s("snapshot JSON path from record"),
                    "timeout_secs": json!({"type": "integer"})
                },
                "required": ["snapshot"]
            }),
        },
    ]
}

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdin.lock().read_line(&mut line)?;
        if n == 0 {
            break; // EOF: host closed the pipe
        }
        let req: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}
                });
                writeln!(out, "{resp}")?;
                out.flush()?;
                continue;
            }
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!({}));
        // JSON-RPC 2.0: notifications (no id) MUST NOT receive a response.
        if id.is_none() {
            continue;
        }
        let id = id.unwrap_or(Value::Null);
        // method is mandatory for requests
        if method.is_empty() {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32600, "message": "invalid request: missing method"}
            });
            writeln!(out, "{resp}")?;
            out.flush()?;
            continue;
        }
        // Unknown methods get a top-level error object (JSON-RPC 2.0 §5.1),
        // not a result envelope.
        if !matches!(method, "initialize" | "ping" | "tools/list" | "tools/call") {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("method not found: {method}")}
            });
            writeln!(out, "{resp}")?;
            out.flush()?;
            continue;
        }
        let result = handle(method, &params)?;
        let resp = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        });
        writeln!(out, "{resp}")?;
        out.flush()?;
    }
    Ok(())
}

fn handle(method: &str, params: &Value) -> Result<Value> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
        })),
        "ping" => Ok(json!({})),
        "tools/list" => {
            let list: Vec<Value> = tools()
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.desc,
                        "inputSchema": t.schema,
                    })
                })
                .collect();
            Ok(json!({ "tools": list }))
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(name, &args) {
                Ok(text) => Ok(json!({
                    "content": [ { "type": "text", "text": text } ]
                })),
                Err(e) => Ok(json!({
                    "content": [ { "type": "text", "text": format!("error: {e}") } ],
                    "isError": true
                })),
            }
        }
        _ => Ok(json!({
            "code": -32601,
            "message": format!("method not found: {method}")
        })),
    }
}

/// Dispatch a tool call; returns the textual (JSON) result for the model.
fn call_tool(name: &str, a: &Value) -> Result<String> {
    let p = |k: &str| -> Result<String> {
        match a.get(k) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(v) => anyhow::bail!("parameter '{k}' must be a string, got {}", type_name(v)),
        }
    };
    let pi = |k: &str, d: i64| -> Result<i64> {
        match a.get(k) {
            None | Some(Value::Null) => Ok(d),
            Some(Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("parameter '{k}' must be an integer")),
            Some(v) => anyhow::bail!("parameter '{k}' must be an integer, got {}", type_name(v)),
        }
    };
    let pb = |k: &str, d: bool| -> Result<bool> {
        match a.get(k) {
            None | Some(Value::Null) => Ok(d),
            Some(Value::Bool(b)) => Ok(*b),
            Some(v) => anyhow::bail!("parameter '{k}' must be a boolean, got {}", type_name(v)),
        }
    };
    let ps = |k: &str| -> Result<Vec<String>> {
        match a.get(k) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(arr)) => {
                let mut out = Vec::new();
                for v in arr {
                    match v {
                        Value::String(s) => out.push(s.clone()),
                        other => anyhow::bail!(
                            "parameter '{k}' must be an array of strings, found {} element",
                            type_name(other)
                        ),
                    }
                }
                Ok(out)
            }
            Some(v) => anyhow::bail!(
                "parameter '{k}' must be an array of strings, got {}",
                type_name(v)
            ),
        }
    };
    let popt = |k: &str| -> Result<Option<String>> {
        match a.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(v) => anyhow::bail!("parameter '{k}' must be a string, got {}", type_name(v)),
        }
    };
    match name {
        "inspect" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::inspect(&bin)?)
        }
        "sections" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::sections(&bin, true)?)
        }
        "symbols" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            let limit = match a.get("limit") {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) => Some(
                    n.as_i64()
                        .ok_or_else(|| anyhow::anyhow!("parameter 'limit' must be an integer"))?
                        as usize,
                ),
                Some(v) => {
                    anyhow::bail!("parameter 'limit' must be an integer, got {}", type_name(v))
                }
            };
            ok(cmd_analyze::symbols(
                &bin,
                &p("filter")?,
                popt("kind")?.as_deref(),
                limit,
                true,
            )?)
        }
        "search" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_search::search(
                &bin,
                &p("pattern")?,
                pi("max", 200)? as usize,
                true,
            )?)
        }
        "xrefs" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_search::xrefs(&bin, &p("target")?, true)?)
        }
        "imports" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::imports(&bin, true)?)
        }
        "exports" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::exports(&bin, true)?)
        }
        "resources" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::resources(&bin, true)?)
        }
        "functions" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            let limit = match a.get("limit") {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) => Some(
                    n.as_i64()
                        .ok_or_else(|| anyhow::anyhow!("parameter 'limit' must be an integer"))?
                        as usize,
                ),
                Some(_) => return Err(anyhow::anyhow!("parameter 'limit' must be an integer")),
            };
            ok(cmd_analyze::functions(&bin, true, limit)?)
        }
        "strings" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            let limit = match a.get("limit") {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) => Some(
                    n.as_i64()
                        .ok_or_else(|| anyhow::anyhow!("parameter 'limit' must be an integer"))?
                        as usize,
                ),
                Some(v) => {
                    anyhow::bail!("parameter 'limit' must be an integer, got {}", type_name(v))
                }
            };
            ok(cmd_analyze::strings(
                &bin,
                pi("min_len", 4)? as usize,
                &p("filter")?,
                limit,
                pb("utf16", false)?,
                true,
            )?)
        }
        "hex" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::hex(
                &bin,
                &p("start")?,
                pi("len", 256)? as u64,
                true,
            )?)
        }
        "disasm" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            let len = match a.get("len") {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) => Some(
                    n.as_i64()
                        .ok_or_else(|| anyhow::anyhow!("parameter 'len' must be an integer"))?
                        as u64,
                ),
                Some(v) => {
                    anyhow::bail!("parameter 'len' must be an integer, got {}", type_name(v))
                }
            };
            ok(cmd_analyze::disasm(
                &bin,
                &p("start")?,
                pi("count", 40)? as usize,
                len,
                pb("until_ret", false)?,
                true,
            )?)
        }
        "hash" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            ok(cmd_analyze::hash(&bin, true)?)
        }
        "entropy" => {
            let bin = crate::core::Binary::load(&p("path")?)?;
            let window = match a.get("window") {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) => Some(
                    n.as_i64()
                        .ok_or_else(|| anyhow::anyhow!("parameter 'window' must be an integer"))?
                        as u64,
                ),
                Some(v) => anyhow::bail!(
                    "parameter 'window' must be an integer, got {}",
                    type_name(v)
                ),
            };
            ok(cmd_analyze::entropy(
                &bin,
                &p("start")?,
                pi("len", 4096)? as u64,
                window,
                true,
            )?)
        }
        "compare" => ok(cmd_mod::compare(&p("path_a")?, &p("path_b")?, 16, true)?),
        "patch" => ok(cmd_mod::patch(
            &p("path")?,
            &p("at")?,
            &p("bytes")?,
            popt("output")?.as_deref(),
            true,
            pb("backup", false)?,
        )?),
        "carve" => ok(cmd_mod::carve(
            &p("path")?,
            true,
            pi("min_size", 0)? as u64,
        )?),
        "extract" => ok(cmd_mod::extract(
            &p("path")?,
            &p("offset")?,
            pi("size", 0)? as u64,
            &p("output")?,
            true,
        )?),
        "run" => ok(cmd_run::run(
            &p("path")?,
            &ps("args")?,
            pi("timeout_secs", 10)? as u64,
            true,
            &ps("env")?,
            popt("cwd")?.as_deref(),
        )?),
        "record" => ok(cmd_run::record(
            &p("path")?,
            &ps("args")?,
            &p("snapshot")?,
            popt("stdin_file")?.as_deref(),
            pi("timeout_secs", 10)? as u64,
            popt("cwd")?.as_deref(),
            &ps("env")?,
            true,
            popt("watch_dir")?.as_deref(),
        )?),
        "replay" => {
            ok(cmd_run::replay(
                &p("snapshot")?,
                match a.get("timeout_secs") {
                    None | Some(Value::Null) => None,
                    Some(Value::Number(n)) => Some(n.as_i64().ok_or_else(|| {
                        anyhow::anyhow!("parameter 'timeout_secs' must be an integer")
                    })? as u64),
                    Some(v) => anyhow::bail!(
                        "parameter 'timeout_secs' must be an integer, got {}",
                        type_name(v)
                    ),
                },
                true,
            )?)
        }
        _ => anyhow::bail!("unknown tool: {name}"),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Extract the JSON payload from an Out for the MCP response.
fn ok(o: crate::out::Out) -> Result<String> {
    // All command fns above are called with json=true, so the payload is JSON.
    match o {
        crate::out::Out::Json(v) => Ok(serde_json::to_string_pretty(&v)?),
        crate::out::Out::Text(t) => Ok(t),
        crate::out::Out::RawJson(s) => Ok(s),
    }
}
