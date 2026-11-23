//! bin-anything — a swiss-army tool for AI agents to work with compiled
//! binaries (ELF/PE): inspect, analyze, compare, patch, carve and observe
//! their behavior. Works as a CLI and as an MCP server.

mod cmd_analyze;
mod cmd_mod;
mod cmd_run;
mod cmd_search;
mod core;
mod disasm;
mod elf;
mod hashes;
mod mcp;
mod mdpad;
mod out;
mod pe;
mod sha256;
#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Parse a number that may be decimal or 0x-prefixed hex (for CLI args).
fn hexnum(s: &str) -> Result<u64, String> {
    if let Some(r) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(r, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

#[derive(Parser)]
#[command(
    name = "bin-anything",
    version,
    about = "Swiss-army CLI + MCP server for AI agents to inspect, analyze, compare, patch and observe compiled binaries (ELF/PE)",
    disable_help_subcommand = true
)]
struct Cli {
    /// Emit JSON (default for machine consumption; text is for humans)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// High-level overview: format, arch, entry, counts, mitigations
    Inspect {
        /// Binary file
        path: String,
    },
    /// List sections (vaddr, offset, sizes, flags, entropy)
    Sections {
        /// Binary file
        path: String,
    },
    /// List symbols (ELF symtab+dynsym; PE exports)
    Symbols {
        /// Binary file
        path: String,
        /// Substring filter (case-insensitive)
        #[arg(long, default_value = "")]
        filter: String,
        /// Kind filter: func|object|section|file|unknown
        #[arg(long)]
        kind: Option<String>,
        /// Show at most N symbols (with total count)
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Search for byte patterns with wildcards (?? matches any byte)
    Search {
        /// Binary file
        path: String,
        /// Pattern: \\xNN escapes, ASCII, ?? or .. wildcards (e.g. '\\xe8??\\xff\\xff\\xff')
        pattern: String,
        /// Maximum matches to report
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Find code/data references to an address or symbol
    Xrefs {
        /// Binary file
        path: String,
        /// Target: 0xADDR | symbol
        target: String,
    },
    /// List imports (ELF: undefined dynsyms; PE: import table)
    Imports {
        /// Binary file
        path: String,
    },
    /// List PE resource tree (types, names, languages, data leaves)
    Resources {
        /// Binary file
        path: String,
    },
    /// List function boundaries in code sections (prologues + symbols)
    Functions {
        /// Binary file
        path: String,
        /// Show at most N functions (with total count)
        #[arg(long)]
        limit: Option<usize>,
    },
    /// List exports
    Exports {
        /// Binary file
        path: String,
    },
    /// Extract printable strings
    Strings {
        /// Binary file
        path: String,
        /// Minimum length
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        /// Substring filter
        #[arg(long, default_value = "")]
        filter: String,
        /// Show at most N strings (with total count)
        #[arg(long)]
        limit: Option<usize>,
        /// Extract UTF-16LE strings (Windows binaries) instead of ASCII
        #[arg(long, default_value_t = false)]
        utf16: bool,
    },
    /// Hex dump a range
    Hex {
        /// Binary file
        path: String,
        /// Start: 0xADDR (vaddr) | +OFFSET (file offset) | symbol
        start: String,
        /// Bytes to show (1..=4096)
        #[arg(long, default_value_t = 256)]
        len: u64,
    },
    /// Disassemble x86/x64 code
    Disasm {
        /// Binary file
        path: String,
        /// Start: 0xADDR | +OFFSET | symbol
        start: String,
        /// Max instructions
        #[arg(long, default_value_t = 40)]
        count: usize,
        /// Alternative to count: disassemble exactly LEN bytes (dec or 0x-hex)
        #[arg(long, value_parser = hexnum)]
        len: Option<u64>,
        /// Stop at the first ret/iret (whole current function)
        #[arg(long, default_value_t = false, conflicts_with = "count")]
        until_ret: bool,
    },
    /// File hashes (SHA-256, CRC32, FNV-1a)
    Hash {
        /// Binary file
        path: String,
    },
    /// Shannon entropy of a range
    Entropy {
        /// Binary file
        path: String,
        /// Start: 0xADDR | +OFFSET | symbol
        start: String,
        /// Bytes (dec or 0x-hex)
        #[arg(long, default_value_t = 4096, value_parser = hexnum)]
        len: u64,
        /// Emit a per-window entropy profile (packed/encrypted region finder)
        #[arg(long, value_parser = hexnum)]
        window: Option<u64>,
    },
    /// Byte-level diff of two binaries
    Compare {
        path_a: String,
        path_b: String,
        /// Max hex chunk samples in output
        #[arg(long, default_value_t = 16)]
        max_chunks: usize,
    },
    /// Patch bytes at address/offset/symbol
    Patch {
        /// Input binary
        path: String,
        /// Where: 0xADDR | +OFFSET | symbol
        at: String,
        /// New bytes: \xNN escapes or literal ASCII
        bytes: String,
        /// Output file (default: overwrite in place)
        #[arg(long)]
        output: Option<String>,
        /// Create <input>.bak before overwriting
        #[arg(long, default_value_t = false)]
        backup: bool,
    },
    /// Find embedded objects (PE/ELF/gzip/ZIP/PNG/JPEG)
    Carve {
        path: String,
        /// Minimum object size (dec or 0x-hex)
        #[arg(long, default_value_t = 0, value_parser = hexnum)]
        min_size: u64,
    },
    /// Extract a byte range into a file
    Extract {
        path: String,
        /// File offset (e.g. 0x400)
        offset: String,
        /// Size in bytes (dec or 0x-hex)
        #[arg(value_parser = hexnum)]
        size: u64,
        output: String,
    },
    /// Run the binary and capture exit/stdout/stderr
    Run {
        path: String,
        /// Arguments for the target
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
        /// Timeout seconds
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        /// Extra env K=V (repeatable)
        #[arg(long = "env")]
        env: Vec<String>,
        /// Working directory
        #[arg(long)]
        cwd: Option<String>,
    },
    /// Record a behavior snapshot to JSON
    Record {
        path: String,
        /// Snapshot output file
        #[arg(long)]
        snapshot: String,
        /// Arguments for the target
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        /// File to feed on stdin
        #[arg(long)]
        stdin_file: Option<String>,
        /// Timeout seconds
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
        /// Working directory
        #[arg(long)]
        cwd: Option<String>,
        /// Extra env K=V (repeatable)
        #[arg(long = "env")]
        env: Vec<String>,
        /// Directory to hash before/after (detect created/changed files)
        #[arg(long)]
        watch_dir: Option<String>,
    },
    /// Re-run from a snapshot and diff behavior
    Replay {
        /// Snapshot JSON from record
        snapshot: String,
        /// Timeout seconds (default: use the timeout recorded in the snapshot)
        #[arg(long)]
        timeout_secs: Option<u64>,
    },
    /// Start the MCP server (stdio JSON-RPC)
    Mcp,
    /// Print MCP client configuration snippets
    McpSetup {
        /// Host app: claude|cursor|generic
        #[arg(long, default_value = "generic")]
        app: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<()> {
    let json = cli.json;
    let out: out::Out = match cli.command {
        Commands::Inspect { path } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::inspect(&bin)?
        }
        Commands::Sections { path } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::sections(&bin, json)?
        }
        Commands::Symbols {
            path,
            filter,
            kind,
            limit,
        } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::symbols(&bin, &filter, kind.as_deref(), limit, json)?
        }
        Commands::Search { path, pattern, max } => {
            let bin = core::Binary::load(&path)?;
            cmd_search::search(&bin, &pattern, max, json)?
        }
        Commands::Xrefs { path, target } => {
            let bin = core::Binary::load(&path)?;
            cmd_search::xrefs(&bin, &target, json)?
        }
        Commands::Imports { path } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::imports(&bin, json)?
        }
        Commands::Resources { path } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::resources(&bin, json)?
        }
        Commands::Functions { path, limit } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::functions(&bin, json, limit)?
        }
        Commands::Exports { path } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::exports(&bin, json)?
        }
        Commands::Strings {
            path,
            min_len,
            filter,
            limit,
            utf16,
        } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::strings(&bin, min_len, &filter, limit, utf16, json)?
        }
        Commands::Hex { path, start, len } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::hex(&bin, &start, len, json)?
        }
        Commands::Disasm {
            path,
            start,
            count,
            len,
            until_ret,
        } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::disasm(&bin, &start, count, len, until_ret, json)?
        }
        Commands::Hash { path } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::hash(&bin, json)?
        }
        Commands::Entropy {
            path,
            start,
            len,
            window,
        } => {
            let bin = core::Binary::load(&path)?;
            cmd_analyze::entropy(&bin, &start, len, window, json)?
        }
        Commands::Compare {
            path_a,
            path_b,
            max_chunks,
        } => cmd_mod::compare(&path_a, &path_b, max_chunks, json)?,
        Commands::Patch {
            path,
            at,
            bytes,
            output,
            backup,
        } => cmd_mod::patch(&path, &at, &bytes, output.as_deref(), json, backup)?,
        Commands::Carve { path, min_size } => cmd_mod::carve(&path, json, min_size)?,
        Commands::Extract {
            path,
            offset,
            size,
            output,
        } => cmd_mod::extract(&path, &offset, size, &output, json)?,
        Commands::Run {
            path,
            args,
            timeout_secs,
            env,
            cwd,
        } => cmd_run::run(&path, &args, timeout_secs, json, &env, cwd.as_deref())?,
        Commands::Record {
            path,
            snapshot,
            args,
            stdin_file,
            timeout_secs,
            cwd,
            env,
            watch_dir,
        } => cmd_run::record(
            &path,
            &args,
            &snapshot,
            stdin_file.as_deref(),
            timeout_secs,
            cwd.as_deref(),
            &env,
            json,
            watch_dir.as_deref(),
        )?,
        Commands::Replay {
            snapshot,
            timeout_secs,
        } => cmd_run::replay(&snapshot, timeout_secs, json)?,
        Commands::Mcp => {
            mcp::serve()?;
            return Ok(());
        }
        Commands::McpSetup { app } => {
            return print_mcp_setup(&app);
        }
    };
    out.print(json)?;
    Ok(())
}

fn print_mcp_setup(app: &str) -> Result<()> {
    let exe = std::env::current_exe()?.to_string_lossy().into_owned();
    let snippet = match app {
        "claude" => format!(
            r#"# Claude Code / Claude Desktop
# Add to claude_desktop_config.json ("mcpServers") or run:
claude mcp add bin-anything -- {exe} mcp
"#
        ),
        "cursor" => format!(
            r#"# Cursor — .cursor/mcp.json
{{
  "mcpServers": {{
    "bin-anything": {{
      "command": "{exe}",
      "args": ["mcp"]
    }}
  }}
}}
"#
        ),
        _ => format!(
            r#"# Generic MCP stdio server config
{{
  "mcpServers": {{
    "bin-anything": {{
      "command": "{exe}",
      "args": ["mcp"]
    }}
  }}
}}
"#
        ),
    };
    println!("{snippet}");
    Ok(())
}
