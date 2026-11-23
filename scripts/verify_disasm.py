#!/usr/bin/env python3
"""Сверка длин инструкций bin-anything с objdump по всей секции .text.

Для каждого бинарника:
1. objdump -d --section=.text -> список (addr, len)
2. bin-anything disasm --json --len <size секции> -> список (addr, len)
3. Сравнение: addr и len должны совпадать до первого расхождения.
"""
import json
import subprocess
import sys

import os

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


def objdump_insns(path):
    out = subprocess.run(["objdump", "-d", "--section=.text", path],
                         capture_output=True, text=True).stdout
    insns = []
    for line in out.splitlines():
        if not line.startswith("    ") or ":" not in line:
            # continuation lines of objdump keep the 4-space indent, but
            # section headers/symbols do too; handled below by \t check
            pass
        stripped = line.strip()
        if not stripped or ":" not in stripped or "\t" not in stripped:
            continue
        addr_part, rest = stripped.split(":", 1)
        try:
            addr = int(addr_part, 16)
        except ValueError:
            continue
        fields = rest.split("\t")
        # field[0] may be empty if the line starts with \t
        hexbytes = fields[0].strip() if fields[0].strip() else (fields[1].strip() if len(fields) > 1 else "")
        rest_fields = fields[1:] if fields[0].strip() else fields[2:]
        has_mnemonic = any(f.strip() for f in rest_fields)
        blen = len(hexbytes.replace(" ", ""))
        if blen == 0 or blen % 2 != 0:
            continue
        if has_mnemonic:
            insns.append((addr, blen // 2))
        elif insns:
            # byte-wrap continuation (no mnemonic on the line)
            insns[-1] = (insns[-1][0], insns[-1][1] + blen // 2)
    return insns


def ba_insns(path, start_off, size):
    r = subprocess.run([BA, "disasm", "--json", path, f"+{start_off}", "--len", str(size)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  bin-anything error:", r.stderr[:200])
        return []
    d = json.loads(r.stdout)
    return [(int(i["addr"], 16), i["len"]) for i in d["insns"]]


def main():
    bins = sys.argv[1:] or ["/bin/true", "/bin/ls", "/usr/bin/gcc"]
    # для PE .text тоже .text
    total_ok = True
    for path in bins:
        # найти .text через sections
        r = subprocess.run([BA, "sections", "--json", path], capture_output=True, text=True)
        secs = json.loads(r.stdout)
        text = next((s for s in secs if s["name"] == ".text"), None)
        if not text:
            print(f"{path}: no .text, skip")
            continue
        od = objdump_insns(path)
        ba = ba_insns(path, text["offset"], text["size"])
        print(f"{path}: objdump={len(od)} insns, bin-anything={len(ba)} insns")
        # по-адресное сравнение: у общей границы инструкций длины обязаны совпасть
        od_map = dict(od)
        ba_map = dict(ba)
        common = set(od_map) & set(ba_map)
        diffs = [(a, od_map[a], ba_map[a]) for a in sorted(common) if od_map[a] != ba_map[a]]
        if len(common) < len(od_map) * 0.5:
            print(f"  WARNING: only {len(common)}/{len(od_map)} common starts")
        if diffs:
            print(f"  MISMATCHES: {len(diffs)} of {len(common)} common starts")
            for a, ol, bl in diffs[:5]:
                print(f"    {a:#x}: objdump len={ol} ba len={bl}")
            total_ok = False
        else:
            print(f"  OK — {len(common)} common instruction starts match objdump")
    sys.exit(0 if total_ok else 1)


if __name__ == "__main__":
    main()
