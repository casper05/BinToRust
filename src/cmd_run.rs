//! Behavior commands: run, record, replay.
//!
//! `record` captures stdout/stderr, exit code, runtime, and hashes of output
//! files into a JSON "behavior snapshot"; `replay` re-runs and compares with a
//! snapshot (like rust-anything's record → diff, but for finished binaries).

use crate::out::Out;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Serialize, Deserialize, Default)]
pub struct Snapshot {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    /// the watchdog killed the process (SIGKILL after timeout)
    #[serde(default)]
    pub timed_out: bool,
    pub duration_ms: u128,
    pub stdout_len: usize,
    pub stderr_len: usize,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_head: String,
    pub stderr_head: String,
    pub files_created: BTreeMap<String, String>, // path -> sha256
    pub recorded_at_unix: u64,
    pub note: String,
    /// Extra env K=V entries applied at record time (replayed for determinism).
    #[serde(default)]
    pub env: Vec<String>,
    /// stdin payload recorded from --stdin-file (embedded so the snapshot is
    /// self-contained; capped at 64 KiB, larger inputs are referenced by path).
    #[serde(default)]
    pub stdin_data: Option<String>,
    /// hex of stdin_data bytes
    #[serde(default)]
    pub stdin_sha256: Option<String>,
    /// timeout used at record time, seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

/// Cap captured stdout/stderr so a chatty target cannot exhaust agent memory:
/// 16 MiB per stream; the hash still covers only the captured prefix and
/// `stdout_truncated` says whether bytes were dropped.
const OUTPUT_CAP: usize = 16 * 1024 * 1024;

fn default_timeout() -> u64 {
    10
}

/// Raw result of one execution.
struct RunOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    killed_by_timeout: bool,
}

/// Run a command and capture its behavior.
#[allow(clippy::too_many_arguments)]
pub fn record(
    bin_path: &str,
    args: &[String],
    snapshot_path: &str,
    stdin_file: Option<&str>,
    timeout_secs: u64,
    cwd: Option<&str>,
    env: &[String],
    json: bool,
    watch_dir: Option<&str>,
) -> Result<Out> {
    let stdin_data = match stdin_file {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("cannot read stdin file {p}"))?),
        None => None,
    };
    let extra_env = parse_env(env)?;
    let watch = watch_dir.map(Path::new);
    let before = snapshot_files(watch);
    let t0 = Instant::now();
    let output = run_simple(
        bin_path,
        args,
        stdin_data.as_deref(),
        timeout_secs,
        cwd,
        &extra_env,
    )?;
    let duration = t0.elapsed().as_millis();
    let after = snapshot_files(watch);

    let mut files_created = BTreeMap::new();
    for (path, sha) in &after {
        if before.get(path) != Some(sha) {
            files_created.insert(path.clone(), sha.clone());
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // embed stdin payload (hex) so replay is self-contained
    const STDIN_CAP: usize = 64 * 1024;
    let (stdin_hex, stdin_sha) = match &stdin_data {
        Some(d) if d.len() <= STDIN_CAP => (Some(hex::encode(d)), Some(crate::sha256::sha256(d))),
        Some(d) => (
            None,
            Some(crate::sha256::sha256(d)), // hash only; too big to embed
        ),
        None => (None, None),
    };
    let snap = Snapshot {
        argv: std::iter::once(bin_path.to_string())
            .chain(args.iter().cloned())
            .collect(),
        cwd: cwd.map(|c| c.to_string()),
        exit_code: output.status.code(),
        signal: unix_signal(&output.status),
        timed_out: output.killed_by_timeout,
        duration_ms: duration,
        stdout_len: output.stdout.len(),
        stderr_len: output.stderr.len(),
        stdout_sha256: crate::sha256::sha256(&output.stdout),
        stderr_sha256: crate::sha256::sha256(&output.stderr),
        stdout_head: head(&stdout, 512),
        stderr_head: head(&stderr, 512),
        files_created,
        recorded_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        note: if output.stdout_truncated || output.stderr_truncated {
            format!(
                "output capped at {OUTPUT_CAP} bytes per stream (stdout truncated: {}, stderr truncated: {})",
                output.stdout_truncated, output.stderr_truncated
            )
        } else {
            String::new()
        },
        env: env.to_vec(),
        stdin_data: stdin_hex,
        stdin_sha256: stdin_sha,
        timeout_secs,
    };
    if !snapshot_path.is_empty() {
        std::fs::write(
            snapshot_path,
            serde_json::to_vec_pretty(&snap).context("serialize snapshot")?,
        )
        .with_context(|| format!("cannot write snapshot {snapshot_path}"))?;
    }
    if json {
        Ok(Out::json(&snap))
    } else {
        Ok(Out::text(format_snapshot(&snap)))
    }
}

fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn unix_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

fn snapshot_files(dir: Option<&Path>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(d) = dir {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_file() {
                    if let Ok(data) = std::fs::read(&p) {
                        m.insert(
                            p.to_string_lossy().into_owned(),
                            crate::sha256::sha256(&data),
                        );
                    }
                }
            }
        }
    }
    m
}

fn format_snapshot(s: &Snapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!("argv: {:?}\n", s.argv));
    out.push_str(&format!(
        "exit: {} (signal {:?}){}, {} ms\n",
        s.exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into()),
        s.signal,
        if s.timed_out { " [TIMED OUT]" } else { "" },
        s.duration_ms
    ));
    out.push_str(&format!(
        "stdout: {} bytes (sha256 {})\n",
        s.stdout_len,
        &s.stdout_sha256[..16]
    ));
    out.push_str(&format!(
        "stderr: {} bytes (sha256 {})\n",
        s.stderr_len,
        &s.stderr_sha256[..16]
    ));
    if !s.stdout_head.is_empty() {
        out.push_str(&format!("--- stdout head ---\n{}\n", s.stdout_head));
    }
    if !s.stderr_head.is_empty() {
        out.push_str(&format!("--- stderr head ---\n{}\n", s.stderr_head));
    }
    if !s.files_created.is_empty() {
        out.push_str("--- files changed ---\n");
        for (p, sha) in &s.files_created {
            out.push_str(&format!("  {p} ({})\n", &sha[..16]));
        }
    }
    out
}

fn parse_env(env: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for e in env {
        let (k, v) = e
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("bad --env entry (expected K=V): {e}"))?;
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Run a command and capture its behavior.
///
/// The target runs in its own process group. Reader threads drain the pipes
/// up to the cap; the watchdog kills the *whole group* (negative pgid), so
/// daemons the target forked cannot keep the pipes open forever. The wait
/// loop is deadline-bounded: if readers still have not seen EOF shortly
/// after the deadline (a grandchild that survived the group kill and holds
/// the pipe), we give up, record what we have, kill the group again and
/// leak only the reader threads — `run` itself always returns.
#[allow(clippy::too_many_arguments)]
fn run_simple(
    bin_path: &str,
    args: &[String],
    stdin_data: Option<&[u8]>,
    timeout_secs: u64,
    cwd: Option<&str>,
    extra_env: &[(String, String)],
) -> Result<RunOutput> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    // Become a child subreaper: any descendant that daemonizes (double-fork
    // or setsid escape) reparents to US instead of init, so after the run we
    // can find and kill the leftovers. Without this a setsid'd grandchild is
    // invisible: its parent (setsid) exits immediately, giving it PPID=1.
    set_child_subreaper();
    let mut cmd = Command::new(bin_path);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        // own process group == child pid; kill(-pgid) reaches grandchildren
        .process_group(0);
    if let Some(c) = cwd {
        cmd.current_dir(c);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| {
        // execvp reports ENOENT both for "file does not exist" and for
        // "not found in PATH"; a bare name without '/' resolved through PATH.
        // Give the agent an honest diagnosis instead.
        if e.kind() == std::io::ErrorKind::NotFound {
            if !bin_path.contains('/') {
                if std::path::Path::new(bin_path).is_file() {
                    return anyhow::anyhow!(
                        "failed to spawn {bin_path}: file exists but is not executable here (check exec bit / format)"
                    );
                }
                return anyhow::anyhow!(
                    "failed to spawn {bin_path}: not found (no '/' in path, searched $PATH; use ./name for the current directory)"
                );
            }
            if std::path::Path::new(bin_path).is_file() {
                return anyhow::anyhow!(
                    "failed to spawn {bin_path}: exists but not executable (check exec bit)"
                );
            }
            return anyhow::anyhow!("failed to spawn {bin_path}: no such file");
        }
        anyhow::anyhow!("failed to spawn {bin_path}: {e}")
    })?;
    if let Some(data) = stdin_data {
        if let Some(mut si) = child.stdin.take() {
            let d = data.to_vec();
            // write in a thread to avoid pipe-full deadlocks
            std::thread::spawn(move || {
                let _ = si.write_all(&d);
            });
        }
    } else {
        drop(child.stdin.take());
    }
    // stdout/stderr readers with a cap; results arrive over a channel so the
    // main thread can stop waiting on a deadline instead of blocking forever
    let mut out_pipe = child.stdout.take().context("no stdout pipe")?;
    let mut err_pipe = child.stderr.take().context("no stderr pipe")?;
    let (res_tx, res_rx) = std::sync::mpsc::channel::<(&'static str, Vec<u8>, bool)>();
    let res_tx_err = res_tx.clone();
    let t_out = std::thread::spawn(move || {
        let (buf, tr) = read_capped(&mut out_pipe, OUTPUT_CAP);
        let _ = res_tx.send(("out", buf, tr));
    });
    let t_err = std::thread::spawn(move || {
        let (buf, tr) = read_capped(&mut err_pipe, OUTPUT_CAP);
        let _ = res_tx_err.send(("err", buf, tr));
    });
    let pgid = child.id() as i32;
    let child_pid = child.id() as i32;
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        let mut killed = false;
        if rx
            .recv_timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
            .is_err()
        {
            // timeout: kill the whole process group (child + grandchildren),
            // then sweep /proc for descendants that escaped the group via
            // setsid and kill them individually (the child is still a zombie
            // here, so their PPID still points at it)
            kill_group(pgid);
            kill_descendants(child_pid);
            killed = true;
        }
        killed
    });
    let mut status = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    // deadline for the child itself; after that, a short grace window for the
    // readers, then we abandon them (they stay parked on the pipe until the
    // OS closes it — the leaked reader threads die with the process)
    let deadline =
        std::time::Duration::from_secs(timeout_secs.max(1)) + std::time::Duration::from_secs(2);
    let t0 = std::time::Instant::now();
    let mut swept = false;
    // short grace after the child exits before sweeping daemon orphans; the
    // hard deadline (timeout + 2 s) remains the outer bound on waiting
    let grace = std::time::Duration::from_millis(300);
    loop {
        if status.is_none() {
            if let Some(st) = child.try_wait().context("wait failed")? {
                status = Some(st);
            }
        }
        // drain whatever the readers reported so far
        while let Ok((which, buf, tr)) = res_rx.try_recv() {
            match which {
                "out" => {
                    stdout = buf;
                    stdout_truncated = tr;
                }
                _ => {
                    stderr = buf;
                    stderr_truncated = tr;
                }
            }
        }
        let readers_done = t_out.is_finished() && t_err.is_finished();
        if status.is_some() && readers_done {
            break;
        }
        // child exited but readers still parked: a daemonized descendant
        // holds the pipe. As subreaper we already own it — kill orphans once
        // the child is gone and readers are still stuck after a short grace
        // period, so EOF arrives and we finish well before the hard deadline.
        if status.is_some() && !readers_done && !swept && t0.elapsed() > grace {
            kill_reparented_orphans(child_pid);
            swept = true;
        }
        if t0.elapsed() > deadline {
            // a grandchild survived the group kill and still holds the pipe:
            // take what we have, kill the group once more, sweep orphans and
            // stop waiting
            kill_group(pgid);
            if !swept {
                kill_descendants(child_pid);
            }
            if status.is_none() {
                status = Some(
                    child
                        .wait()
                        .unwrap_or_else(|_| std::process::ExitStatus::default()),
                );
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = tx.send(());
    let killed_by_timeout = watchdog.join().unwrap_or(false);
    let status = status.context("no exit status")?;
    // final sweep: as subreaper we now parent every orphaned descendant of
    // the target (setsid/double-fork daemons). Kill any child that is not
    // our main child (already reaped) so nothing outlives the run.
    kill_reparented_orphans(child_pid);
    Ok(RunOutput {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        // SIGKILL from the watchdog while the process had no other signal
        killed_by_timeout: killed_by_timeout && status.code().is_none(),
    })
}

/// Read from a pipe up to `cap` bytes; return (bytes, truncated).
fn read_capped<R: Read>(r: &mut R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < cap {
                    let room = cap - buf.len();
                    buf.extend_from_slice(&chunk[..n.min(room)]);
                    if n > room {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (buf, truncated)
}

/// Become a child subreaper (Linux prctl PR_SET_CHILD_SUBREAPER = 36):
/// orphaned descendants reparent to us instead of init, making daemon
/// leftovers findable after the run. Best-effort: on non-Linux or old
/// kernels this is a no-op and the sweep simply finds nothing.
fn set_child_subreaper() {
    extern "C" {
        fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    }
    const PR_SET_CHILD_SUBREAPER: i32 = 36;
    unsafe {
        let _ = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
}

/// SIGKILL reparented orphans: our own children (per /proc PPID scan) other
/// than the main target child. Only meaningful as a subreaper; the reader
/// threads of run_simple are threads, not processes, so they never match.
fn kill_reparented_orphans(main_child: i32) {
    let my_pid = std::process::id() as i32;
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut victims = Vec::new();
    for e in dir.flatten() {
        let name = match e.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == main_child {
            continue;
        }
        let stat = match std::fs::read_to_string(e.path().join("stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ppid = match stat.rsplit_once(')') {
            Some((_, rest)) => rest
                .split_whitespace()
                .nth(1)
                .and_then(|f| f.parse::<i32>().ok()),
            None => continue,
        };
        if ppid == Some(my_pid) {
            victims.push(pid);
        }
    }
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    for pid in victims {
        unsafe {
            kill(pid, 9);
        }
    }
}

/// SIGKILL a whole process group (child + any grandchildren), negative pgid.
fn kill_group(pgid: i32) {
    // std::os::unix::process::CommandExt::kill is per-pid, so use the raw
    // syscall via the `kill` wrapper libc exposes on every Linux; declared
    // here to stay dependency-free.
    fn raw_kill(pid: i32, sig: i32) -> i32 {
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        unsafe { kill(pid, sig) }
    }
    let _ = raw_kill(-pgid, 9); // negative pid == process group
    let _ = raw_kill(pgid, 9); // and the leader itself
}

/// SIGKILL every descendant of `root` (transitively), including ones that
/// escaped our process group via setsid. Reads /proc/*/stat and walks the
/// PPID chain; must run while `root` is still a zombie (before wait()),
/// otherwise orphans are reparented to init and become untraceable.
fn kill_descendants(root: i32) {
    // pid -> ppid snapshot of the process table
    let mut table: Vec<(i32, i32)> = Vec::new();
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };
    for e in dir.flatten() {
        let name = e.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // stat field 4 is ppid; comm (field 2) may contain spaces, so parse
        // from the closing ')' to stay robust against weird process names
        let stat = match std::fs::read_to_string(e.path().join("stat")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ppid = match stat.rsplit_once(')') {
            Some((_, rest)) => rest.split_whitespace().nth(1).and_then(|f| f.parse().ok()),
            None => continue,
        };
        if let Some(ppid) = ppid {
            table.push((pid, ppid));
        }
    }
    // BFS from root: collect all descendants, kill deepest-first so children
    // die before they can spawn replacements
    let mut frontier = vec![root];
    let mut victims: Vec<i32> = Vec::new();
    while let Some(p) = frontier.pop() {
        for &(pid, ppid) in &table {
            if ppid == p && !victims.contains(&pid) {
                victims.push(pid);
                frontier.push(pid);
            }
        }
    }
    for &pid in victims.iter().rev() {
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        unsafe {
            kill(pid, 9);
        }
    }
}

/// Replay: run again and diff against a snapshot.
/// `timeout_secs_override`: Some(t) forces a timeout, None uses the recorded one.
pub fn replay(snapshot_path: &str, timeout_secs_override: Option<u64>, json: bool) -> Result<Out> {
    let raw = std::fs::read(snapshot_path)
        .with_context(|| format!("cannot read snapshot {snapshot_path}"))?;
    let snap: Snapshot = serde_json::from_slice(&raw).context("bad snapshot JSON")?;
    let bin_path = snap.argv.first().context("snapshot has no argv")?.clone();
    let args: Vec<String> = snap.argv[1..].to_vec();

    // replay the recorded environment, stdin payload and (unless overridden)
    // the recorded timeout for faithful re-execution
    let extra_env = parse_env(&snap.env)?;
    let stdin_bytes = snap
        .stdin_data
        .as_deref()
        .map(hex::decode)
        .transpose()
        .context("bad stdin_data hex in snapshot")?;
    let effective_timeout = match timeout_secs_override {
        Some(t) => t,
        None => snap.timeout_secs,
    };
    let watch = snap.cwd.as_deref().map(Path::new);
    let before = snapshot_files(watch);
    let t0 = Instant::now();
    let output = run_simple(
        &bin_path,
        &args,
        stdin_bytes.as_deref(),
        effective_timeout,
        snap.cwd.as_deref(),
        &extra_env,
    )?;
    let duration = t0.elapsed().as_millis();
    let after = snapshot_files(watch);

    let mut files_created = BTreeMap::new();
    for (path, sha) in &after {
        if before.get(path) != Some(sha) {
            files_created.insert(path.clone(), sha.clone());
        }
    }

    let stdout_sha = crate::sha256::sha256(&output.stdout);
    let stderr_sha = crate::sha256::sha256(&output.stderr);
    let exit_now = output.status.code();
    let signal_now = unix_signal(&output.status);
    let timed_out_now = output.killed_by_timeout;

    #[derive(Serialize)]
    struct FieldDiff {
        field: String,
        expected: serde_json::Value,
        actual: serde_json::Value,
        match_: bool,
    }
    let mut fields: Vec<FieldDiff> = vec![];
    let mut cmp = |name: &str, expected: serde_json::Value, actual: serde_json::Value| {
        let m = expected == actual;
        fields.push(FieldDiff {
            field: name.to_string(),
            expected,
            actual,
            match_: m,
        });
    };
    cmp(
        "exit_code",
        serde_json::json!(snap.exit_code),
        serde_json::json!(exit_now),
    );
    cmp(
        "signal",
        serde_json::json!(snap.signal),
        serde_json::json!(signal_now),
    );
    cmp(
        "timed_out",
        serde_json::json!(snap.timed_out),
        serde_json::json!(timed_out_now),
    );
    cmp(
        "stdout_sha256",
        serde_json::json!(snap.stdout_sha256),
        serde_json::json!(stdout_sha),
    );
    cmp(
        "stderr_sha256",
        serde_json::json!(snap.stderr_sha256),
        serde_json::json!(stderr_sha),
    );
    cmp(
        "files_created",
        serde_json::json!(snap.files_created),
        serde_json::json!(files_created),
    );
    let all_match = fields.iter().all(|f| f.match_);
    let v = serde_json::json!({
        "snapshot": snapshot_path,
        "argv": snap.argv,
        "duration_ms": duration,
        "match": all_match,
        "fields": fields,
    });
    if json {
        Ok(Out::json(&v))
    } else {
        let mut s = String::new();
        s.push_str(&format!("replay of {:?}\n", snap.argv));
        s.push_str(&format!(
            "overall: {}\n",
            if all_match { "MATCH" } else { "DIFFER" }
        ));
        for f in &fields {
            let mark = if f.match_ { "ok  " } else { "DIFF" };
            s.push_str(&format!(
                "  [{mark}] {}: expected {} actual {}\n",
                f.field, f.expected, f.actual
            ));
        }
        Ok(Out::text(s))
    }
}

/// One-shot run (no snapshot): show exit code, stdout, stderr.
pub fn run(
    bin_path: &str,
    args: &[String],
    timeout_secs: u64,
    json: bool,
    env: &[String],
    cwd: Option<&str>,
) -> Result<Out> {
    let extra_env = parse_env(env)?;
    let t0 = Instant::now();
    let output = run_simple(bin_path, args, None, timeout_secs, cwd, &extra_env)?;
    let duration = t0.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let v = serde_json::json!({
        "argv": std::iter::once(bin_path.to_string()).chain(args.iter().cloned()).collect::<Vec<_>>(),
        "exit_code": output.status.code(),
        "signal": unix_signal(&output.status),
        "timed_out": output.killed_by_timeout,
        "duration_ms": duration,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": output.stdout_truncated,
        "stderr_truncated": output.stderr_truncated,
    });
    if json {
        Ok(Out::json(&v))
    } else {
        let mut s = String::new();
        s.push_str(&format!(
            "exit: {} (signal {:?}){} in {duration} ms\n",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            unix_signal(&output.status),
            if output.killed_by_timeout {
                " [TIMED OUT]"
            } else {
                ""
            }
        ));
        s.push_str(&format!(
            "--- stdout ({} bytes{}) ---\n{}",
            output.stdout.len(),
            if output.stdout_truncated {
                ", truncated"
            } else {
                ""
            },
            stdout
        ));
        s.push_str(&format!(
            "--- stderr ({} bytes{}) ---\n{}",
            output.stderr.len(),
            if output.stderr_truncated {
                ", truncated"
            } else {
                ""
            },
            stderr
        ));
        Ok(Out::text(s))
    }
}
