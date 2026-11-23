#!/usr/bin/env python3
"""Operand-level conformance metric for bin-anything e2e.

Compares our disassembly against objdump on the *same* instruction starts
and reports the share of matching mnemonics and matching mnemonic+operand
pairs. Normalization strips objdump-only sugar (PTR qualifiers, `# addr`
comments, `<symbol>` annotations, `ds:`) so the metric measures real
decoding differences, not formatting.

The subprocess exit code is checked before parsing: a killed (OOM) or
crashed binary is reported honestly instead of crashing with
JSONDecodeError on empty output.

Exit code 0 if both thresholds pass. Usage:
    operand_metric.py <binary> <section> <start> <len> <mnem_min_pct> <full_min_pct> <label> [bin-anything]
"""
import json
import os
import re
import subprocess
import sys


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

DEFAULT_BA = os.environ.get("BA") or _default_ba()


def norm_ops(s: str) -> str:
    for q in ("DWORD PTR ", "QWORD PTR ", "WORD PTR ", "BYTE PTR ", "XMMWORD PTR "):
        s = s.replace(q, "")
    s = re.sub(r"\s*#.*$", "", s)      # lea rip comments: "# 70fb <sym>"
    s = re.sub(r"\s*<[^>]*>", "", s)   # symbol annotations
    s = s.replace("ds:", "")
    # our RIP-relative annotations carry the resolved address:
    # "[rip+0x18b] = 0x11f6" vs objdump "[rip+0x18b]" — same decode, extra info
    s = re.sub(r"=\s*0x[0-9a-f]+", "", s)
    s = s.replace(" ", "").replace("[", "").replace("]", "")
    # zero displacement: [rax+0x0] == [rax] (objdump prints the +0x0 form)
    s = s.replace("+0x0,", ",").replace("+0x0", "")
    return s


def die(label: str, msg: str) -> int:
    print(f"FAIL {label}: {msg}")
    return 1


def main() -> int:
    path, section, start = sys.argv[1], sys.argv[2], sys.argv[3]
    length = int(sys.argv[4], 0)  # dec or 0x-hex
    mnem_min, full_min, label = float(sys.argv[5]), float(sys.argv[6]), sys.argv[7]
    ba = sys.argv[8] if len(sys.argv) > 8 else DEFAULT_BA

    od = subprocess.run(
        ["objdump", "-d", "-M", "intel", f"--section={section}", path],
        capture_output=True, text=True, timeout=600,
    )
    if od.returncode != 0:
        return die(label, f"objdump rc={od.returncode}")
    ref = {}
    for line in od.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*\t(\S+)\s*(.*)", line)
        if m:
            ref[int(m.group(1), 16)] = (m.group(2), m.group(3).strip())

    r = subprocess.run(
        [ba, "--json", "disasm", path, start, "--len", str(length)],
        capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:
        return die(label, f"bin-anything rc={r.returncode}"
                          + (" (SIGKILL — OOM?)" if r.returncode == -9 else ""))
    try:
        insns = json.loads(r.stdout)["insns"]
    except (json.JSONDecodeError, KeyError) as e:
        return die(label, f"unparsable JSON output ({e.__class__.__name__});"
                          f" stderr: {r.stderr[:200]!r}")
    ours = {int(i["addr"], 16): (i["mnemonic"], i["operands"]) for i in insns}

    common = set(ref) & set(ours)
    if not common:
        return die(label, f"no common instruction starts (objdump {len(ref)},"
                          f" ours {len(ours)})")
    mn = sum(1 for a in common if ref[a][0] == ours[a][0])
    full = sum(
        1 for a in common
        if ref[a][0] == ours[a][0] and norm_ops(ref[a][1]) == norm_ops(ours[a][1])
    )
    pct_m, pct_f = 100 * mn / len(common), 100 * full / len(common)
    ok_m, ok_f = pct_m >= mnem_min, pct_f >= full_min
    print(f"{'ok' if ok_m and ok_f else 'FAIL'} {label}: "
          f"mnemonics {pct_m:.2f}% (min {mnem_min:.0f}%), full pairs {pct_f:.2f}% (min {full_min:.0f}%) "
          f"on {len(common)} common starts")
    return 0 if (ok_m and ok_f) else 1


if __name__ == "__main__":
    sys.exit(main())
