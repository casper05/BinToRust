#!/usr/bin/env python3
"""opcode_coverage.py — R4 decoder-coverage harness for bin-anything.

Generates a synthetic opcode corpus (every one-byte opcode plus curated
rare/edge families), wraps it in minimal ELF32/ELF64 containers, decodes each
window with the bin-anything `disasm` subcommand and cross-checks instruction
boundaries (lengths) and mnemonic families against capstone (the reference).

Outputs:
  --json  machine summary {per-mode totals, mismatches by category, coverage}
  --text  human table

Exit code 0 = coverage >= threshold and no length mismatches (CI gate);
1 = below threshold or length mismatches found.

Categories of mismatch:
  LEN    — instruction boundary differs from capstone (critical: desyncs a
           linear sweep)
  MNEM   — mnemonic family differs (informational; port uses family sketches)
  PANIC  — the tool crashed on a valid encoding (critical)
  DB     — port emitted `db` where capstone decodes a real instruction

Coverage definition (R4): share of the 256 one-byte opcodes (per mode) for
which the port produces the same instruction length as capstone on a canonical
encoding, plus a fixed family battery (0F xx, VEX, x87, groups) that must pass
length checks. The number reported is the length-agreement percentage; the
family battery is a pass/fail count reported alongside.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile

import capstone

BIN = os.environ.get("BIN_ANYTHING", "./target/release/bin-anything")

# --------------------------------------------------------------------------
# Minimal ELF builders (one PT_LOAD, code at file offset 0x1000 == vaddr)
# --------------------------------------------------------------------------

def make_elf(code: bytes, path: str, is64: bool) -> None:
    ehsz, phsz = (64, 56) if is64 else (52, 32)
    data = bytearray(b"\x00" * (0x1000 + len(code) + 16))
    if is64:
        eh = struct.pack(
            "<4sBBBBB7xHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0,
            2, 0x3E, 1, 0, 0x1000, ehsz, 0, ehsz, phsz, 1, 0, 0, 0)
        ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, 0x1000,
                         len(data), 0x1000)
    else:
        eh = struct.pack(
            "<4sBBBBB7xHHIIIIIHHHHHH", b"\x7fELF", 1, 1, 1, 0, 0,
            2, 3, 1, 0, 0x1000, ehsz, 0, ehsz, phsz, 1, 0, 0, 0)
        ph = struct.pack("<IIIIIIII", 1, 5, 0, 0x1000, 0x1000, 0x1000,
                         len(data), 0x1000)
    data[0:ehsz] = eh
    data[ehsz:ehsz + phsz] = ph
    data[0x1000:0x1000 + len(code)] = code
    with open(path, "wb") as f:
        f.write(bytes(data))


# --------------------------------------------------------------------------
# Corpus generation
# --------------------------------------------------------------------------
# Canonical ModRM/SIB/immediate tails so each probe decodes as ONE instruction.
# Using a "calm" tail avoids incidental second-instruction bleed-through: any
# boundary disagreement shows up as a length mismatch directly.

TAIL = bytes([0xC0, 0x00])          # modrm mod=3 reg=0 rm=0 (reg,reg) + imm8
TAIL_W = TAIL + bytes([0x00])       # + extra imm byte for wide-imm forms
TAIL6 = bytes([0xC0, 0, 0, 0, 0])   # reg,reg + imm32


def one_byte_probes(is64: bool):
    """(label, bytes) for each of the 256 one-byte opcodes with a canonical
    encoding. Instructions with implicit immediates get matching tails."""
    probes = []
    for op in range(0x100):
        b = bytes([op])
        # opcodes whose encoding needs extra bytes (canonical Intel forms)
        if op in (0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C, 0x6A,
                  0xA8, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                  0xCD, 0xE4, 0xE5, 0xE6, 0xE7, 0xC0):
            b += bytes([0x7F])                      # + imm8
        elif op in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D,
                    0xA9, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
                    0x68):
            b += bytes([0x34, 0x12, 0x78, 0x56])    # + imm32
        elif op in (0x69, 0x6B, 0x81, 0xC1, 0xC7, 0xF7):
            b += TAIL + bytes([0x78, 0x56, 0x34, 0x12])  # modrm + imm32
        elif op in (0x80, 0x83, 0xC6, 0xF6, 0x69 + 1) and op != 0x6A:
            b += TAIL + bytes([0x7F])               # modrm + imm8
        elif op in (0x82,):
            b += TAIL + bytes([0x7F])
        elif op in (0xC2,):
            b += bytes([0x34, 0x12])                # ret imm16
        elif op in (0xC8,):
            b += bytes([0x34, 0x12, 0x02])          # enter imm16, imm8
        elif op in (0x9A, 0xEA):
            if not is64:
                b += bytes([0, 0, 0, 0, 0, 0])      # callf/jmpf far ptr
        elif op in (0xD4, 0xD5):
            b += bytes([0x0A])                      # aam/aad imm8
        elif op in (0xA0, 0xA1, 0xA2, 0xA3):
            b += bytes([0x00, 0x10, 0x00, 0x00])    # moffs32
        elif op == 0xE8 or op == 0xE9:
            b += bytes([0x02, 0x00, 0x00, 0x00])    # call/jmp rel32
        elif op in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0xEB,
                    0xE0, 0xE1, 0xE2, 0xE3):
            b += bytes([0x10])                      # rel8
        probes.append((f"{op:02x}", b))
    return probes


def family_probes(is64: bool):
    """Curated rare/edge families — the classes that broke the original audit."""
    p = []

    def add(label, b):
        p.append((label, bytes(b)))

    # 0F two-byte map: representative + rare rows
    for op2 in (0x05, 0x0B, 0x10, 0x18, 0x1E, 0x1F, 0x28, 0x2A, 0x38, 0x3A,
                0x40, 0x4A, 0x50, 0x51, 0x57, 0x60, 0x6E, 0x70, 0x71, 0x77,
                0x80, 0x90, 0x9F, 0xA0, 0xA2, 0xA3, 0xA4, 0xA5, 0xAC, 0xAF,
                0xB0, 0xB6, 0xBA, 0xBC, 0xBE, 0xC0, 0xC2, 0xC8, 0xD6, 0xEF):
        add(f"0f_{op2:02x}", [0x0F, op2, 0xC0, 0x00])
    for op2 in (0xA4, 0xAC, 0xC4, 0xC6, 0x71, 0x72, 0x73, 0xBA, 0xC2):
        add(f"0f_{op2:02x}_imm", [0x0F, op2, 0xC0, 0x00, 0x7F])
    # 0F 38 / 0F 3A three-byte maps
    add("0f38_00", [0x0F, 0x38, 0x00, 0xC0, 0x00])
    add("0f3a_0f", [0x0F, 0x3A, 0x0F, 0xC0, 0x00, 0x7F])
    # x87 with memory + register forms
    for row in range(0xD8, 0xE0):
        for reg in (0, 3, 5, 7):
            add(f"x87_{row:02x}_r{reg}", [row, 0xC0 | (reg << 3) | 1, 0x00])
    add("x87_d9c0", [0xD9, 0xC0])
    add("x87_dfe0", [0xDF, 0xE0])          # fnstsw ax
    add("x87_9b_glue", [0x9B, 0xDF, 0xE0])  # fstsw via fwait glue
    # groups F6/F7/FE/FF all reg fields
    for reg in range(8):
        add(f"f7_r{reg}", [0xF7, 0xC0 | (reg << 3) | 2, 0x78, 0x56, 0x34, 0x12])
        add(f"ff_r{reg}", [0xFF, 0xC0 | (reg << 3) | 1])
    # rare legacy: lds/les/lss/lfs/lgs (32-bit only), arpl, bound, salc, xlat
    if not is64:
        add("lds", [0xC5, 0xC0, 0x00])
        add("les", [0xC4, 0xC0, 0x00])
        add("arpl", [0x63, 0xC0, 0x00])
        add("bound", [0x62, 0xC0, 0x00])
        add("pusha", [0x60])
        add("popa", [0x61])
        add("callf", [0x9A, 0, 0, 0, 0, 0x23, 0])
        add("jmpf", [0xEA, 0, 0, 0, 0, 0x23, 0])
    add("salc", [0xD6])
    add("xlat", [0xD7])
    add("into", [0xCE])
    add("int1", [0xF1])
    # prefixes glued to opcodes (lock/rep/seg/66/addrsize)
    add("lock_add", [0xF0, 0x01, 0xC0])
    add("rep_movsb", [0xF3, 0xA4])
    add("repne_scasb", [0xF2, 0xAE])
    add("fs_mov", [0x64, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00])
    add("66_add", [0x66, 0x05, 0x34, 0x12])
    add("67_modrm", [0x67, 0x8B, 0x00])
    add("66_67", [0x66, 0x67, 0x8B, 0x00])
    # REX variants (64-bit only)
    if is64:
        add("rexw_add", [0x48, 0x01, 0xC0])
        add("rex_mov_imm64", [0x48, 0xB8] + [0xAA] * 8)
        add("rexr_byte", [0x44, 0x88, 0xC0])
        add("rexb_sib", [0x41, 0x8B, 0x04, 0x01])     # mov eax,[r9+rax]
        add("movsxd", [0x48, 0x63, 0xC0])
        add("sib_nobase", [0x8B, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00])
        add("rip_rel", [0x8B, 0x05, 0x10, 0x00, 0x00, 0x00])
        add("rex_c7", [0x48, 0xC7, 0xC0, 0x39, 0x05, 0x00, 0x00])
    else:
        add("abs_disp32", [0x8B, 0x05, 0x00, 0x10, 0x00, 0x00])
        add("sib_nobase32", [0x8B, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00])
    # string family full set
    for op in (0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
               0x6C, 0x6D, 0x6E, 0x6F):
        add(f"str_{op:02x}", [op])
    # VEX (64-bit) — AVX/AVX2
    if is64:
        add("vex3_vzeroupper", [0xC5, 0xF8, 0x77])
        add("vex2_vzeroupper", [0xC5, 0xF8, 0x77])
        add("vex3_vmovups", [0xC4, 0xE1, 0x7C, 0x10, 0xC1])
        add("vex3_vzeroall", [0xC5, 0xFC, 0x77])
        add("vex_vaddps", [0xC5, 0xFC, 0x58, 0xC1])
        add("vex_vpshufd", [0xC4, 0xE1, 0x79, 0x70, 0xC1, 0x7F])
        add("vex_vpsllq", [0xC4, 0xE1, 0xF9, 0x73, 0xF1, 0x7F])
    # misc traps
    add("cs_seg_prefix", [0x2E, 0x8B, 0x00])
    add("ss_seg_prefix", [0x36, 0x8B, 0x00])
    add("ds_seg_prefix", [0x3E, 0x8B, 0x00])
    add("es_seg_prefix", [0x26, 0x8B, 0x00])
    return p


# Known, documented differences vs the capstone reference — the port follows
# objdump (Intel syntax) where the two references disagree. Each entry:
# probe label -> reason.
KNOWN_DIFFERENCES = {
    # objdump renders `9b df e0` as ONE insn "fstsw %ax" (fwait glues forward
    # onto the x87 opcode); capstone splits it into "wait; fnstsw". Port
    # matches objdump, so exclude from the capstone comparison.
    "x87_9b_glue": "fwait glue: port follows objdump (fstsw), capstone splits",
}

# Legitimate alias pairs: the port names an instruction the way objdump does
# in Intel syntax, capstone shows its own (often AT&T-flavoured) variant.
# These are NOT defects: same encoding, same length, different spelling.
MNEM_ALIASES = {
    ("pusha", "pushal"), ("popa", "popal"),
    ("callf", "lcall"), ("jmpf", "ljmp"),
    ("fwait", "wait"),
    ("cmpps", "cmpeqps"),  # capstone bakes the imm8 predicate into the name
    ("movabs", "mov"),
    # D9 D9 is an undocumented FSTP variant: objdump shows (bad), capstone
    # names it fstpnce; the port's conservative "fpu" is deliberate.
    ("fpu", "fstpnce"),
}

# --------------------------------------------------------------------------
# Probe runner
# --------------------------------------------------------------------------
def run_probe(binary: str, is64: bool, payload: bytes, workdir: str,
              label: str):
    """Wrap `payload` in an ELF, disassemble a window and return
    (port_len, port_mnem, ref_len, ref_mnem, err)."""
    path = os.path.join(workdir, f"probe_{label}.elf")
    make_elf(payload, path, is64)
    r = subprocess.run(
        [binary, "disasm", path, "+0x1000", "--len", str(len(payload)),
         "--json"],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not r.stdout.strip().startswith("{"):
        return None, None, None, None, (r.stderr or r.stdout)[:300]

    insns = json.loads(r.stdout)["insns"]
    port_len = insns[0]["len"] if insns else 0
    port_mnem = insns[0]["mnemonic"] if insns else ""

    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    ref = next(md.disasm(payload, 0), None)
    if ref is None:
        # capstone itself refuses: not a decodable instruction — skip
        return port_len, port_mnem, None, None, None
    return port_len, port_mnem, ref.size, ref.mnemonic, None


def mnemonic_family(m: str) -> str:
    """Normalize a mnemonic to a comparison family (port sketches names)."""
    if m == "db" or m == "":
        return "db"
    m = m.lower()
    if m.startswith("op_0f_") or m.startswith("vex") or m.startswith("xop"):
        return "family-synthetic"
    for fam in ("movzx", "movsx", "movsxd", "mov", "cmov", "set", "j", "call",
                "loop", "push", "pop", "add", "sub", "imul", "mul", "div",
                "idiv", "inc", "dec", "and", "or", "xor", "not", "neg", "cmp",
                "test", "xchg", "lea", "shl", "shr", "sar", "rol", "ror",
                "rcl", "rcr", "shld", "shrd", "bt", "bts", "btr", "btc",
                "bsf", "bsr", "bswap", "nop", "ret", "leave", "enter", "int",
                "iret", "fadd", "fmul", "fcom", "fsub", "fdiv", "fld", "fst",
                "fild", "fist", "fxch", "fnop", "emms", "vadd", "vmul",
                "vsub", "vdiv", "vmov", "vpshuf", "vpsll", "vpsrl", "vzero",
                "endbr", "cdq", "cwd", "cqo", "cdqe", "cwde", "sahf", "lahf",
                "pushf", "popf", "stos", "lods", "scas", "movs", "cmps",
                "ins", "outs", "xlat", "aam", "aad", "salc", "in", "out",
                "hlt", "rdtsc", "cpuid", "syscall", "sysenter"):
        if m.startswith(fam) and (m == fam or not m[len(fam)].isalpha()):
            return fam
    return m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=BIN)
    ap.add_argument("--threshold", type=float, default=90.0,
                    help="min one-byte length-agreement %% (default 90)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-report", type=int, default=40,
                    help="max mismatches printed in text mode")
    args = ap.parse_args()

    report = {"tool": "opcode_coverage", "binary": args.binary,
              "modes": {}, "threshold": args.threshold, "pass": None}
    gate_ok = True

    with tempfile.TemporaryDirectory(prefix="ocv_") as workdir:
        for is64 in (False, True):
            mode = "x64" if is64 else "i386"
            probes = one_byte_probes(is64) + family_probes(is64)
            len_mism, mnem_mism, panics, dbs, ref_skip = [], [], [], [], 0
            ok_onebyte, total_onebyte = 0, 0
            fam_total, fam_len_ok = 0, 0

            for label, payload in probes:
                if label in KNOWN_DIFFERENCES:
                    continue
                pl, pm, rl, rm, err = run_probe(
                    args.binary, is64, payload, workdir, f"{mode}_{label}")
                if err is not None and pl is None:
                    panics.append({"probe": label, "error": err,
                                   "bytes": payload.hex()})
                    continue
                if rl is None:
                    ref_skip += 1
                    continue
                onebyte = len(label) <= 2  # one-byte probes have hex labels
                if onebyte:
                    total_onebyte += 1
                else:
                    fam_total += 1
                if pl != rl:
                    len_mism.append({"probe": label, "bytes": payload.hex(),
                                     "port_len": pl, "ref_len": rl,
                                     "port": pm, "ref": rm})
                    continue
                if onebyte:
                    ok_onebyte += 1
                else:
                    fam_len_ok += 1
                if pm == "db" and rm not in ("db", ""):
                    dbs.append({"probe": label, "bytes": payload.hex(),
                                "ref": rm})
                elif (pm, rm) in MNEM_ALIASES:
                    pass  # documented objdump-vs-capstone spelling difference
                elif mnemonic_family(pm) != mnemonic_family(rm):
                    mnem_mism.append({"probe": label, "bytes": payload.hex(),
                                      "port": pm, "ref": rm})

            cov = (100.0 * ok_onebyte / total_onebyte) if total_onebyte else 0
            report["modes"][mode] = {
                "one_byte": {"total": total_onebyte, "len_ok": ok_onebyte,
                             "coverage_pct": round(cov, 2)},
                "families": {"total": fam_total, "len_ok": fam_len_ok},
                "len_mismatches": len_mism,
                "mnem_mismatches": mnem_mism,
                "db_where_ref_decodes": dbs,
                "panics": panics,
                "ref_skipped": ref_skip,
            }
            if cov < args.threshold or len_mism or panics:
                gate_ok = False

    report["pass"] = gate_ok
    if args.json:
        print(json.dumps(report, indent=1))
    else:
        for mode, m in report["modes"].items():
            print(f"== {mode}")
            ob = m["one_byte"]
            print(f"  one-byte length agreement: {ob['len_ok']}/{ob['total']}"
                  f" = {ob['coverage_pct']:.2f}%")
            fam = m["families"]
            print(f"  family battery: {fam['len_ok']}/{fam['total']}")
            print(f"  LEN mismatches: {len(m['len_mismatches'])}  "
                  f"MNEM: {len(m['mnem_mismatches'])}  "
                  f"DB-vs-ref: {len(m['db_where_ref_decodes'])}  "
                  f"PANIC: {len(m['panics'])}  ref-skip: {m['ref_skipped']}")
            for e in (m["panics"] + m["len_mismatches"] +
                      m["db_where_ref_decodes"])[:args.max_report]:
                print(f"    {e.get('probe')}: {e.get('bytes')} "
                      f"port={e.get('port', e.get('port_len'))} "
                      f"ref={e.get('ref', e.get('ref_len'))}")
        print(f"PASS={gate_ok} (threshold {args.threshold}%)")
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
