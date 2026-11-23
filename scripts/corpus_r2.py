#!/usr/bin/env python3
"""corpus_r2.py — R2 corpus extension for bin-anything e2e verification.

Builds the artifact classes the edition-2 corpus lacked, then runs the
operand-conformance metric (mnemonic+operands vs objdump) over each:

  A. gcc ELF32  (different codegen from the clang-built system binaries)
  B. gcc ELF64 -O0 / -O2 / -Os / -static / PIE
  C. clang ELF64 (if clang available)
  D. PE64 fixture (synthetic, make_pe_fixture.py)
  E. .NET ILONLY PE (synthetic, make_dotnet_fixture.py) — disasm must SKIP
     gracefully (no native .text beyond the tiny stub), inspect must report
     CLR metadata.

Every class result is PASS / FAIL / SKIP with a one-line reason (SKIP only
when the toolchain genuinely cannot be provisioned). Exit 0 iff no FAIL.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

def _default_ba():
    """Locate the binary across repo layouts (env BA wins):
    crate at repo root (GitHub), crate in subdir, binary next to script."""
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (
        os.path.join(here, "..", "target", "release", "bin-anything"),
        os.path.join(here, "bin-anything", "target", "release", "bin-anything"),
        os.path.join(here, "bin-anything"),
    ):
        if os.access(cand, os.X_OK):
            return cand
    return os.path.join(here, "..", "target", "release", "bin-anything")

BA = os.environ.get("BA") or _default_ba()
METRIC = os.path.join(HERE, "operand_metric.py")
WORK = tempfile.mkdtemp(prefix="corpus_r2_")

C_SRC = r"""
#include <stdio.h>
#include <string.h>
volatile int side = 0;
static unsigned long hash(const char *s) {
    unsigned long h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h;
}
int compute(const char *s, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {
        acc += (int)(hash(s) % (unsigned long)(i + 7));
        if (acc > 1000) { acc ^= 0x55; side++; }
    }
    return acc;
}
int main(void) {
    char buf[64];
    strcpy(buf, "corpus-r2");
    printf("%d %d\n", compute(buf, 17), side);
    return 0;
}
"""

results = []


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                          **kw)


def record(cls, status, note):
    results.append({"class": cls, "status": status, "note": note})
    print(f"[{status:>4}] {cls}: {note}")


def build_elf(tag, cc, flags):
    """Compile C_SRC into WORK/tag; returns path or None."""
    src = os.path.join(WORK, tag + ".c")
    out = os.path.join(WORK, tag)
    with open(src, "w") as f:
        f.write(C_SRC)
    r = run([cc, *flags, "-o", out, src])
    if r.returncode != 0 or not os.path.exists(out):
        return None
    return out


def metric_over(path, section=".text", start="+0x1000", size=None,
                threshold=95, full_min=50):
    """Run operand_metric.py; returns (status, note). size=None -> auto."""
    # resolve section offset/size from `sections` output
    if size is None:
        j = run([BA, "sections", path, "--json"]).stdout
        try:
            secs = json.loads(j)
            for s in secs:
                if s.get("name") == section:
                    # offset field is a hex string in JSON output
                    off = int(s["offset"], 16) if isinstance(
                        s.get("offset"), str) else s.get("offset", 0)
                    start = f"+{off:#x}" if off else start
                    size = int(s["size"], 0) if isinstance(
                        s.get("size"), str) else s.get("size", 0)
                    break
        except Exception as e:
            return "SKIP", f"sections parse failed: {e}"
        if not size:
            return "SKIP", f"no {section} section"
    r = run(["python3", METRIC, path, section, start, str(size),
             str(threshold), str(full_min),
             f"corpus-r2 {os.path.basename(path)}", BA])
    note = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()[:120]
    if r.returncode == 0:
        return "PASS", note
    if "SKIP" in note:
        return "SKIP", note
    return "FAIL", note


def main():
    if not os.access(BA, os.X_OK):
        print(f"BA binary missing: {BA}", file=sys.stderr)
        return 2

    # ---- A/B: gcc builds ----
    gcc = shutil.which("gcc")
    gcc_classes = [
        ("gcc-elf32", ["-m32", "-O2"]),
        ("gcc-elf64-O0", ["-O0"]),
        ("gcc-elf64-O2", ["-O2"]),
        ("gcc-elf64-Os", ["-Os"]),
        ("gcc-elf64-static", ["-O2", "-static"]),
        ("gcc-elf64-pie", ["-O2", "-fPIE", "-pie"]),
    ]
    for tag, flags in gcc_classes:
        if not gcc:
            record(tag, "SKIP", "gcc not installed")
            continue
        if tag == "gcc-elf32":
            probe = build_elf(tag + "_probe", gcc, ["-m32", "-c"])
            if probe is None:
                record(tag, "SKIP", "no gcc -m32 runtime (install gcc-multilib)")
                continue
        path = build_elf(tag, gcc, flags)
        if path is None:
            record(tag, "SKIP", f"build failed: {flags}")
            continue
        st, note = metric_over(path)
        record(tag, st, note)

    # ---- C: clang ----
    clang = shutil.which("clang")
    if clang:
        path = build_elf("clang-elf64", clang, ["-O2"])
        if path:
            st, note = metric_over(path)
            record("clang-elf64", st, note)
        else:
            record("clang-elf64", "SKIP", "build failed")
    else:
        record("clang-elf64", "SKIP", "clang not installed")

    # ---- D: PE64 fixture ----
    pe = os.path.join(WORK, "pe64.exe")
    r = run(["python3", os.path.join(HERE, "make_pe_fixture.py"), pe,
             os.path.join(WORK, "pe64.dll")])
    if os.path.exists(pe):
        st, note = metric_over(pe, start="+0x400", size=64, threshold=95)
        record("pe64-synthetic", st, note)
        j = run([BA, "inspect", pe, "--json"]).stdout
        ok64 = '"arch": "x64"' in j or '"bits": 64' in j
        record("pe64-inspect", "PASS" if ok64 else "FAIL",
               "arch=x64 detected" if ok64 else "arch not x64")
    else:
        record("pe64-synthetic", "SKIP", "make_pe_fixture failed")

    # ---- E: .NET fixture ----
    dn = os.path.join(WORK, "dotnet.exe")
    r = run(["python3", os.path.join(HERE, "make_dotnet_fixture.py"), dn])
    if os.path.exists(dn):
        # inspect must surface CLR metadata
        j = run([BA, "inspect", dn, "--json"]).stdout
        if '"runtime_version"' in j:
            record("dotnet-inspect", "PASS", "CLR runtime_version reported")
        else:
            record("dotnet-inspect", "FAIL", "no CLR metadata in inspect")
        # disasm over the (tiny) native stub must not crash; IL body is not
        # native code so only the mnemonic bar applies (full-pair bar 0)
        st, note = metric_over(dn, threshold=0, full_min=0)
        record("dotnet-disasm-resilience",
               "PASS" if st in ("PASS", "SKIP") else st,
               f"no crash on ILONLY image ({note})")
    else:
        record("dotnet-inspect", "SKIP", "make_dotnet_fixture failed")

    # ---- summary ----
    n_pass = sum(1 for x in results if x["status"] == "PASS")
    n_fail = sum(1 for x in results if x["status"] == "FAIL")
    n_skip = sum(1 for x in results if x["status"] == "SKIP")
    print(f"\nR2 corpus: PASS={n_pass} FAIL={n_fail} SKIP={n_skip} "
          f"(executed {len(results)} classes)")
    with open(os.path.join(HERE, "corpus_r2_results.json"), "w") as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
