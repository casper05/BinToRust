//! Compact x86/x64 instruction decoder + mnemonic annotator (pure Rust).
//!
//! Design goals for an AI-agent-facing disassembler:
//!   1. **Correct lengths** — so a linear sweep never desynchronizes.
//!   2. **Mnemonic + operand sketch** for the common compiler-emitted subset.
//!   3. **Semantic kind, branch target, symbol annotation, resolved
//!      RIP-relative addresses** — the agent reasons about behavior, not
//!      syntax.
//!
//! Unknown/rare opcodes still decode with correct lengths where possible.
//!
//! Length decoding follows the Intel SDM Vol. 2: legacy prefixes, REX, opcode
//! (1-3 bytes), ModRM (+SIB, displacement), immediate.

use crate::core::Binary;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    pub addr: u64,
    pub offset: u64,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    /// resolved direct branch/call target VA
    pub target: Option<u64>,
    /// effective address of a RIP-relative memory operand (data xref)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rip_target: Option<u64>,
    /// symbol name for `target` or a RIP-relative memory operand, if known
    pub target_symbol: Option<String>,
    pub kind: &'static str,
    /// how much to trust this row: "high" = concrete mnemonic from the
    /// tables, "medium" = family sketch (operand sketch may be partial),
    /// "low" = `db` data byte or synthetic placeholder name (op_0f_xx /
    /// vex_0f38 etc.) — the length is still correct, the name is not.
    pub confidence: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum OpKind {
    Nop,
    Call,
    Ret,
    Jmp,
    Jcc,
    Mov,
    Lea,
    Push,
    Pop,
    Arith,
    Logic,
    Shift,
    Cmp,
    Test,
    Syscall,
    Int,
    String,
    Xchg,
    Leave,
    Other,
    Data,
    Privileged,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Nop => "nop",
            OpKind::Call => "call",
            OpKind::Ret => "ret",
            OpKind::Jmp => "jmp",
            OpKind::Jcc => "jcc",
            OpKind::Mov => "mov",
            OpKind::Lea => "lea",
            OpKind::Push => "push",
            OpKind::Pop => "pop",
            OpKind::Arith => "arith",
            OpKind::Logic => "logic",
            OpKind::Shift => "shift",
            OpKind::Cmp => "cmp",
            OpKind::Test => "test",
            OpKind::Syscall => "syscall",
            OpKind::Int => "int",
            OpKind::String => "string",
            OpKind::Xchg => "xchg",
            OpKind::Leave => "leave",
            OpKind::Other => "other",
            OpKind::Data => "data",
            OpKind::Privileged => "priv",
        }
    }
}

pub struct Decoded {
    pub insns: Vec<Insn>,
    /// number of bytes successfully consumed from the requested range
    #[allow(dead_code)]
    pub consumed: usize,
    /// reason decoding stopped early (if any)
    pub stopped: Option<String>,
    /// per-confidence instruction counts: (high, medium, low)
    pub confidence_counts: (usize, usize, usize),
}

pub struct Decoder<'a> {
    pub bin: &'a Binary,
    pub bits64: bool,
    /// sorted (addr, size, name) for symbol annotation
    syms: Vec<(u64, u64, String)>,
}

impl<'a> Decoder<'a> {
    pub fn new(bin: &'a Binary) -> Decoder<'a> {
        let mut syms: Vec<(u64, u64, String)> = bin
            .symbols()
            .into_iter()
            .filter(|s| s.addr != 0)
            .map(|s| (s.addr, s.size, s.name))
            .collect();
        // PE import slots live in the IAT; a call/jmp [slot] resolves to the
        // imported function, so annotate the slot address with its name
        // ("kernel32.dll!CreateFileW"). Slot entries are exact 4/8-byte units,
        // keeping `delta == 0` for the annotate() hit.
        for imp in bin.imports() {
            if imp.addr != 0 {
                syms.push((imp.addr, 0, format!("{}!{}", imp.module, imp.name)));
            }
        }
        syms.sort_by_key(|s| s.0);
        syms.dedup_by_key(|s| s.0);
        Decoder {
            bin,
            bits64: bin.is_64(),
            syms,
        }
    }

    /// All known symbols as (addr, size, name), sorted by address.
    pub fn symbol_list(&self) -> &[(u64, u64, String)] {
        &self.syms
    }

    /// Nearest symbol at or below `addr`.
    pub fn symbol_at(&self, addr: u64) -> Option<(&str, u64)> {
        let idx = self.syms.partition_point(|s| s.0 <= addr);
        if idx == 0 {
            return None;
        }
        let (a, sz, name) = &self.syms[idx - 1];
        let delta = addr - a;
        if delta <= (*sz).max(32) {
            Some((name, delta))
        } else {
            None
        }
    }

    fn annotate(&self, addr: u64) -> Option<String> {
        self.symbol_at(addr).map(|(name, delta)| {
            if delta == 0 {
                format!("<{name}>")
            } else {
                format!("<{name}+{delta:#x}>")
            }
        })
    }

    /// Disassemble up to `max_len` bytes at file `offset` (linear sweep).
    pub fn disasm_at_offset(&self, offset: u64, max_len: usize) -> Decoded {
        let avail = (self.bin.data.len() as u64).saturating_sub(offset);
        let len = (max_len as u64).min(avail) as usize;
        let data = &self.bin.data[offset as usize..offset as usize + len];
        let mut out = Vec::new();
        let mut pos = 0usize;
        // A linear sweep must not die on data islands inside a code section
        // (jump tables, string constants that begin with 0x62/0xc4/0xc5...):
        // when the decoder reports a mid-buffer anomaly ("bad vex map",
        // "bad evex map", "* overrun") we emit that byte as `db` and resync
        // on the next byte, exactly like objdump's behaviour on data. Only
        // genuine buffer-edge truncation ("truncated ...") stops the sweep,
        // because there is nothing left to resync onto.
        let mut resyncs = 0usize;
        let mut first_stop: Option<String> = None;
        while pos < data.len() {
            let (insn, stop) = self.decode_one(data, pos, offset);
            match stop.as_deref() {
                None => {
                    let l = insn.len;
                    out.push(insn);
                    pos += l;
                }
                Some(reason) if reason.starts_with("truncated") => {
                    // hit the end of the window mid-instruction: emit the
                    // partial `db` and stop here
                    out.push(insn);
                    let counts = confidence_counts(&out);
                    return Decoded {
                        insns: out,
                        consumed: pos,
                        stopped: Some(reason.to_string()),
                        confidence_counts: counts,
                    };
                }
                Some(_) => {
                    // mid-buffer anomaly (bad vector map / overrun on data
                    // bytes): emit as `db`, remember it, resync +1
                    if first_stop.is_none() {
                        first_stop = stop;
                    }
                    let l = insn.len.max(1);
                    out.push(insn);
                    resyncs += 1;
                    pos += l;
                }
            }
        }
        let counts = confidence_counts(&out);
        if resyncs > 0 {
            // surface the resyncs so callers can warn about data islands
            Decoded {
                insns: out,
                consumed: pos,
                stopped: first_stop.map(|r| format!("{r} (resynced {resyncs}x)")),
                confidence_counts: counts,
            }
        } else {
            Decoded {
                insns: out,
                consumed: pos,
                stopped: None,
                confidence_counts: counts,
            }
        }
    }

    #[allow(dead_code)]
    pub fn disasm_at_vaddr(&self, vaddr: u64, max_len: usize) -> anyhow::Result<Decoded> {
        let off = self.bin.vaddr_to_offset(vaddr)?;
        Ok(self.disasm_at_offset(off, max_len))
    }

    fn vaddr_of(&self, offset: u64) -> u64 {
        self.bin.offset_to_vaddr(offset).unwrap_or(offset)
    }

    /// Decode one instruction at data[pos..]; base_off = file offset of data[0].
    fn decode_one(&self, data: &[u8], pos: usize, base_off: u64) -> (Insn, Option<String>) {
        let start = pos;
        let end = data.len();
        let mut p = start;

        // ---- prefixes ----
        // Legacy prefixes come first; if a VEX (C4/C5), XOP (8F) or EVEX (62)
        // byte appears after them it is a vector prefix and must terminate the
        // prefix scan (AVX/AVX2/AVX-512 support).
        let mut rex = 0u8;
        let mut opsize = false;
        let mut rep = 0u8;
        let mut lock = false;
        let mut seg: Option<&'static str> = None;
        let mut glued_fwait = false;
        loop {
            if p >= end {
                return (
                    self.db(data, start, base_off),
                    Some("truncated in prefixes".into()),
                );
            }
            match data[p] {
                0x66 => opsize = true,
                0xf2 => rep = 0xf2,
                0xf3 => rep = 0xf3,
                0xf0 => lock = true,
                0x64 => seg = Some("fs"),
                0x65 => seg = Some("gs"),
                0x2e => seg = Some("cs"),
                0x26 => seg = Some("es"),
                0x36 => seg = Some("ss"),
                0x3e => seg = Some("ds"),
                0x67 => {}
                // FWAIT (9B) is a separate instruction per Intel, but objdump
                // and most disassemblers glue it to a following x87 opcode
                // (D8-DF). Before anything else it stays a 1-byte insn.
                // `9b 9b df e0` (fstsw ax with wait, objdump shows one insn)
                // means each 9B glues forward until a non-x87 byte.
                0x9b if p + 1 < end && matches!(data[p + 1], 0x9b | 0xd8..=0xdf) => {
                    glued_fwait = true;
                }
                0x40..=0x4f if self.bits64 => rex = data[p],
                0xc5 if self.bits64 => {
                    if p + 1 >= end {
                        return (
                            self.db(data, start, base_off),
                            Some("truncated vex2".into()),
                        );
                    }
                    return self.decode_vex(data, start, p, end, base_off, data[p + 1], None);
                }
                0xc4 if self.bits64 => {
                    if p + 2 >= end {
                        return (
                            self.db(data, start, base_off),
                            Some("truncated vex3".into()),
                        );
                    }
                    let b1 = data[p + 1];
                    let b2 = data[p + 2];
                    // LES in 64-bit is invalid anyway; only map 1-3 is VEX
                    if (1..=3).contains(&(b1 & 0x1f)) {
                        return self.decode_vex(data, start, p, end, base_off, b2, Some((b1, b2)));
                    }
                }
                0x8f if self.bits64 => {
                    // XOP (AMD): same layout as C4, map field 0x08-0x0a
                    if p + 2 >= end {
                        return (self.db(data, start, base_off), Some("truncated xop".into()));
                    }
                    let b1 = data[p + 1];
                    let b2 = data[p + 2];
                    if (0x08..=0x0a).contains(&(b1 & 0x1f)) {
                        return self.decode_vex(data, start, p, end, base_off, b2, Some((b1, b2)));
                    }
                }
                0x62 if self.bits64 => {
                    if p + 3 >= end {
                        return (
                            self.db(data, start, base_off),
                            Some("truncated evex".into()),
                        );
                    }
                    // EVEX is valid when the third byte's bit2 == 1 (required);
                    // otherwise 62 is BOUND (32-bit) / invalid (64-bit).
                    if data[p + 2] & 0x04 != 0 {
                        return self.decode_evex(
                            data,
                            start,
                            p,
                            end,
                            base_off,
                            (data[p + 1], data[p + 2], data[p + 3]),
                        );
                    }
                }
                _ => break,
            }
            p += 1;
        }
        if p >= end {
            return (
                self.db(data, start, base_off),
                Some("truncated at opcode".into()),
            );
        }
        let op = data[p];
        p += 1;

        // ---- 0F two/three-byte map ----
        if op == 0x0f {
            return self.decode_0f(data, start, p, end, base_off, rex, opsize, rep, lock);
        }

        // ---- one-byte map ----
        let (mnem, mut kind, has_modrm, mut imm) = one_byte(op, rep, opsize, rex, self.bits64);
        let mut mnemonic = mnem.to_string();
        let mut target = None;
        let mut ops = String::new();
        let mut reg_field: u8 = 0;
        let mut rm_str = String::new();
        let mut rip_disp: Option<i64> = None;

        // cwde/cdqe and cdq/cqo: concrete name by mode and operand size
        if op == 0x98 {
            // 66 -> cbw/cwd; REX.W -> cdqe/cqo family member; default cwde
            // (capstone renders plain 98 in x64 as cwde; objdump as cdqe —
            // follow capstone since the port uses Intel syntax)
            mnemonic = if opsize {
                "cbw".into()
            } else if rex_w_set(rex) {
                "cdqe".into()
            } else {
                "cwde".into()
            };
        }
        if op == 0x99 {
            mnemonic = if self.bits64 && !opsize && rex & 8 != 0 {
                "cqo".into()
            } else if opsize {
                "cwd".into()
            } else {
                "cdq".into()
            };
        }
        // string ops: pick the concrete mnemonic (movs/movsb/movsw/movsd,
        // cmpsb/w/d) and glue the rep/repne prefix like objdump does
        if matches!(op, 0xa4..=0xa7) {
            // A4 movsb, A5 movs(w/d), A6 cmpsb, A7 cmps(w/d): bit1 selects
            // movs vs cmps, bit0 selects byte vs sized form
            let base = if op & 2 == 0 { "movs" } else { "cmps" };
            let sfx = string_suffix(op, opsize, self.bits64, rex);
            mnemonic = if rep == 0 {
                format!("{base}{sfx}")
            } else {
                format!("{} {base}{sfx}", if rep == 0xf3 { "rep" } else { "repne" })
            };
            kind = OpKind::String;
        }
        // AA..AF: stos/lods/scas — glue rep/repne like objdump does and pick
        // the concrete suffix (b/w/d/q) from mode + operand size
        if matches!(op, 0xaa..=0xaf) {
            let base = match op {
                0xaa | 0xab => "stos",
                0xac | 0xad => "lods",
                _ => "scas",
            };
            let sfx = string_suffix(op, opsize, self.bits64, rex);
            mnemonic = if rep == 0 {
                format!("{base}{sfx}")
            } else {
                format!("{} {base}{sfx}", if rep == 0xf3 { "rep" } else { "repne" })
            };
            kind = OpKind::String;
        }
        if matches!(op, 0xe8 | 0xe9) {
            // call/jmp rel32
            if p + 4 > end {
                return (
                    self.db(data, start, base_off),
                    Some("truncated call/jmp".into()),
                );
            }
            let rel = i32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as i64;
            let next_v = self.vaddr_of(base_off + (p + 4) as u64);
            target = Some((next_v as i64 + rel) as u64);
            ops = format!("{:#x}", target.unwrap());
            p += 4;
            imm = 0;
        } else if matches!(op, 0xeb | 0x70..=0x7f) {
            // jmp rel8 / jcc rel8
            if op != 0xeb {
                mnemonic = cc_mnemonic(op & 0x0f).to_string();
            }
            if p >= end {
                return (
                    self.db(data, start, base_off),
                    Some("truncated rel8".into()),
                );
            }
            let rel = data[p] as i8 as i64;
            let next_v = self.vaddr_of(base_off + (p + 1) as u64);
            target = Some((next_v as i64 + rel) as u64);
            ops = format!("{:#x}", target.unwrap());
            p += 1;
            imm = 0;
        } else if has_modrm {
            let (m, rs, reg, rd, stopped) = self.eat_modrm(data, p, end, rex, opsize);
            if let Some(r) = stopped {
                return (self.db(data, start, base_off), Some(r));
            }
            p += m;
            reg_field = reg;
            rm_str = rs;
            rip_disp = rd;
            // group-opcode refinement + imm fixups
            // (for group opcodes the reg field extension REX.R is ignored)
            let regg = reg & 7;
            match op {
                0x80..=0x83 => {
                    let g = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][regg as usize];
                    mnemonic = g.to_string();
                    kind = match g {
                        "cmp" => OpKind::Cmp,
                        "and" | "or" | "xor" => OpKind::Logic,
                        _ => OpKind::Arith,
                    };
                }
                0xc0 | 0xc1 | 0xd0..=0xd3 => {
                    let g = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"][regg as usize];
                    mnemonic = g.to_string();
                    kind = OpKind::Shift;
                    if matches!(op, 0xd2 | 0xd3) {
                        ops = format!("{rm_str}, cl");
                    } else if matches!(op, 0xd0 | 0xd1) {
                        ops = format!("{rm_str}, 1");
                    }
                }
                0xf6 | 0xf7 => {
                    let g =
                        ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"][regg as usize];
                    mnemonic = g.to_string();
                    kind = match g {
                        "test" => OpKind::Test,
                        "not" | "neg" => OpKind::Logic,
                        _ => OpKind::Arith,
                    };
                    if reg >= 2 {
                        imm = 0; // only TEST carries an immediate
                    }
                }
                0xd8..=0xdf => {
                    // x87: concrete mnemonic from opcode row + ModRM reg field.
                    // mod=3 (register forms) have a separate st(i) name map.
                    let fpu_reg_form = !rm_str.starts_with('[') && !rm_str.is_empty();
                    mnemonic =
                        fpu_mnemonic(op, reg & 7, x87_rm_index(&rm_str), fpu_reg_form).to_string();
                    // Глитый впереди FWAIT меняет fnstsw -> fstsw (wait-форма);
                    // objdump рендерит `9b 9b df e0` как одну инструкцию fstsw.
                    if glued_fwait && (mnemonic == "fnstsw" || mnemonic == "fnstcw") {
                        mnemonic = mnemonic.replace("fnst", "fst");
                    }
                }
                0xfe | 0xff => {
                    // FF /2 /4 (call/jmp r/m): pointer width is 64-bit in
                    // x86-64 regardless of REX.W — render rax not eax
                    let g = if op == 0xfe {
                        if regg == 0 {
                            "inc"
                        } else {
                            "dec"
                        }
                    } else {
                        ["inc", "dec", "call", "callf", "jmp", "jmpf", "push", "?"][regg as usize]
                    };
                    mnemonic = g.to_string();
                    kind = match g {
                        "call" => OpKind::Call,
                        "jmp" => OpKind::Jmp,
                        "push" => OpKind::Push,
                        "inc" | "dec" => OpKind::Arith,
                        _ => OpKind::Other,
                    };
                }
                _ => {}
            }
        } else {
            // no modrm: derive simple operands (inc/dec/push/pop reg)
            if (0x48..=0x4f).contains(&op) && !self.bits64 {
                // i386 one-byte inc/dec r32
                ops = reg_name(op & 7, opsize, self.bits64).to_string();
            } else if (0x50..=0x5f).contains(&op) {
                ops = reg_name(
                    (op & 7) + if rex & 1 != 0 { 8 } else { 0 },
                    opsize,
                    self.bits64,
                )
                .to_string();
            }
        }

        // FF /2 /4 reg form in x86-64: pointer registers print as 64-bit
        if self.bits64
            && op == 0xff
            && matches!(reg_field & 7, 2 | 4)
            && !rm_str.is_empty()
            && !rm_str.contains('[')
        {
            ops = reg64_name((rm_str_to_index(&rm_str)) as u8, true).to_string();
        }
        // build operands for modrm forms (Intel order: dst, src)
        if has_modrm && ops.is_empty() {
            let regn = reg_name_sized(reg_field, opsize, self.bits64, rex & 8 != 0);
            if !rm_str.is_empty() {
                ops = match op {
                    0x00 | 0x01 | 0x08 | 0x09 | 0x10 | 0x11 | 0x18 | 0x19 | 0x20 | 0x21 | 0x28
                    | 0x29 | 0x30 | 0x31 | 0x38 | 0x39 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88
                    | 0x89 | 0x8c | 0x8e => format!("{rm_str}, {regn}"),
                    0x02 | 0x03 | 0x0a | 0x0b | 0x12 | 0x13 | 0x1a | 0x1b | 0x22 | 0x23 | 0x2a
                    | 0x2b | 0x32 | 0x33 | 0x3a | 0x3b | 0x8a | 0x8b | 0x8d | 0x63 | 0xaf => {
                        format!("{regn}, {rm_str}")
                    }
                    _ => rm_str.clone(),
                };
            }
        }

        // moffs (A0-A3): the immediate is an absolute address; render as a
        // register-pair operand like objdump: "mov eax, ds:0x791068"
        if matches!(op, 0xa0..=0xa3) && imm > 0 && p + imm <= end {
            let addr: u64 = match imm {
                2 => u16::from_le_bytes(data[p..p + 2].try_into().unwrap()) as u64,
                4 => u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as u64,
                _ => u64::from_le_bytes(data[p..p + 8].try_into().unwrap()),
            };
            let rname = match (op, opsize, self.bits64 && rex & 8 != 0) {
                (0xa0, _, _) | (0xa2, _, _) => "al".to_string(),
                (_, true, _) => "ax".to_string(),
                (_, false, true) => "rax".to_string(),
                _ => "eax".to_string(),
            };
            ops = if matches!(op, 0xa0 | 0xa1) {
                format!("{rname}, ds:{addr:#x}")
            } else {
                format!("ds:{addr:#x}, {rname}")
            };
            target = Some(addr);
        }

        // immediate literal
        if imm > 0 && !matches!(op, 0xa0..=0xa3) {
            if p + imm > end {
                return (self.db(data, start, base_off), Some("truncated imm".into()));
            }
            let v: i64 = match imm {
                1 => data[p] as i8 as i64,
                2 => i16::from_le_bytes(data[p..p + 2].try_into().unwrap()) as i64,
                3 => {
                    // ENTER imm16, imm8: read as two separate fields; for the
                    // literal display combine them (size field first).
                    let a = u16::from_le_bytes(data[p..p + 2].try_into().unwrap());
                    let b = data[p + 2] as i64;
                    (a as i64) | (b << 16)
                }
                4 => i32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as i64,
                6 => {
                    // CALLF/JMPF far pointer: imm32 offset + imm16 selector;
                    // render as selector:offset like objdump ("lcall
                    // $0x23,$0x1234").
                    let off = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
                    let sel = u16::from_le_bytes(data[p + 4..p + 6].try_into().unwrap());
                    ((sel as i64) << 32) | off as i64
                }
                _ => i64::from_le_bytes(data[p..p + 8].try_into().unwrap()),
            };
            // far pointer display for CALLF/JMPF (imm == 6): show the real
            // selector:offset pair instead of a concatenated literal
            if imm == 6 && ops.is_empty() {
                let off = (v as u32) as u64;
                let sel = ((v >> 32) as u16) as u64;
                ops = format!("{sel:#x}:{off:#x}");
            }
            // accumulator forms: opcode low nibble 4 = AL,imm8; 5 = eAX,imm;
            // A9 = eAX, imm (test)
            let acc: Option<String> = if matches!(
                op,
                0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0x84 | 0xa8
            ) {
                Some("al".to_string())
            } else if matches!(
                op,
                0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0xa9
            ) {
                Some(if opsize {
                    "ax".to_string()
                } else if self.bits64 && rex & 8 != 0 {
                    "rax".to_string()
                } else {
                    "eax".to_string()
                })
            } else {
                None
            };
            // natural-width display: imm32 without REX.W/66 is shown as u32
            // (objdump prints 0x8007000e, not the sign-extended 64-bit form)
            let shown: u64 = if imm == 4 && !opsize && !(self.bits64 && rex & 8 != 0) {
                v as u32 as u64
            } else if imm == 2 {
                v as u16 as u64
            } else {
                v as u64
            };
            if ops.is_empty() {
                ops = match acc {
                    Some(r) => format!("{r}, {shown:#x}"),
                    None => format!("{shown:#x}"),
                };
            } else if imm != 6 {
                ops.push_str(&format!(", {shown:#x}"));
            }
            if matches!(op, 0xb0..=0xbf) && !has_modrm && self.bits64 && rex & 8 != 0 {
                // objdump/capstone name the 64-bit immediate form movabs
                mnemonic = "movabs".to_string();
            }
            if matches!(op, 0xb0..=0xbf) && !has_modrm {
                // mov reg, imm: register name first; width: imm8 => byte reg,
                // else REX.W ? 64 : 32 bits
                let regn = if matches!(op, 0xb0..=0xb7) {
                    const B: [&str; 16] = [
                        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b",
                        "r11b", "r12b", "r13b", "r14b", "r15b",
                    ];
                    B[((op & 7) + if rex & 1 != 0 { 8 } else { 0 }) as usize].to_string()
                } else {
                    reg_name_sized(
                        (op & 7) + if rex & 1 != 0 { 8 } else { 0 },
                        opsize,
                        self.bits64,
                        rex & 8 != 0,
                    )
                };
                ops = format!("{regn}, {v:#x}");
            }
        }
        // REX.W widens moffs for 0xa1/0xa3 in 64-bit
        if matches!(op, 0xa0..=0xa3) && self.bits64 && !opsize && rex & 8 != 0 {
            // handled via imm length adjustment below
        }

        let total = p - start + imm;
        if start + total > end {
            return (self.db(data, start, base_off), Some("overrun".into()));
        }

        if lock {
            mnemonic = format!("lock {mnemonic}");
        }

        // RIP-relative (x86-64) / absolute [disp32] (i386) resolution
        let insn_va = self.vaddr_of(base_off + start as u64);
        let mut target_symbol = target.and_then(|t| self.annotate(t));
        let mut rip_target = None;
        if let Some(d) = rip_disp {
            // ModRM mod=0 rm=101 means RIP-relative in x86-64 but an absolute
            // [disp32] address in i386; x86-64 with a segment prefix and SIB
            // no-base (fs:0x28) is also absolute.
            let absolute = !self.bits64 || seg.is_some();
            let effective = if absolute {
                d as u64
            } else {
                (insn_va as i64 + total as i64 + d) as u64
            };
            let sym = self.annotate(effective);
            if !absolute {
                ops = format!("{ops} = {effective:#x}");
                rip_target = Some(effective);
            } else if let Some(sg) = seg {
                // glue the segment into the memory operand itself:
                // "rsi, [0x28]" -> "rsi, fs:[0x28]" (objdump: fs:0x28)
                if let Some(pos) = ops.find('[') {
                    ops.insert_str(pos, &format!("{sg}:"));
                } else {
                    ops = format!("{sg}:{ops}");
                }
            } else if target.is_none() && matches!(op, 0xff) && kind == OpKind::Call {
                // call [abs]: annotate the indirect target address
                target = Some(effective);
            }
            target_symbol = target_symbol.or(sym);
        }

        let conf = classify_confidence(&mnemonic);
        (
            Insn {
                addr: insn_va,
                offset: base_off + start as u64,
                len: total,
                bytes: data[start..start + total].to_vec(),
                mnemonic,
                operands: ops,
                target,
                rip_target,
                target_symbol,
                kind: kind.as_str(),
                confidence: conf,
            },
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_0f(
        &self,
        data: &[u8],
        start: usize,
        mut p: usize,
        end: usize,
        base_off: u64,
        rex: u8,
        opsize: bool,
        rep: u8,
        lock: bool,
    ) -> (Insn, Option<String>) {
        if p >= end {
            return (
                self.db(data, start, base_off),
                Some("truncated at 0f".into()),
            );
        }
        let op2 = data[p];
        p += 1;

        // three-byte escapes
        if op2 == 0x38 || op2 == 0x3a {
            if p >= end {
                return (
                    self.db(data, start, base_off),
                    Some("truncated at 0f3x".into()),
                );
            }
            let op3 = data[p];
            p += 1;
            let (m, _rs, reg, _rd, stopped) = self.eat_modrm(data, p, end, rex, opsize);
            if let Some(r) = stopped {
                return (self.db(data, start, base_off), Some(r));
            }
            let imm = if op2 == 0x3a { 1 } else { 0 };
            if p + m + imm > end {
                return (
                    self.db(data, start, base_off),
                    Some("truncated 0f3x tail".into()),
                );
            }
            let total = p + m + imm - start;
            return (
                Insn {
                    addr: self.vaddr_of(base_off + start as u64),
                    offset: base_off + start as u64,
                    len: total,
                    bytes: data[start..start + total].to_vec(),
                    mnemonic: three_byte_mnemonic(op2, op3, reg & 7).to_string(),
                    operands: String::new(),
                    target: None,
                    rip_target: None,
                    target_symbol: None,
                    kind: OpKind::Other.as_str(),
                    confidence: classify_confidence(
                        &three_byte_mnemonic(op2, op3, reg & 7).to_string(),
                    ),
                },
                None,
            );
        }

        let (mnem, kind, has_modrm, mut imm) = map0f(op2, rep, opsize);
        // REX.W widens 0F 6E/7E (movd) into movq
        let mnem_owned: String = match (op2, rex & 8 != 0) {
            (0x6e, true) | (0x7e, true) => "movq".to_string(),
            (0x6e, false) | (0x7e, false) => "movd".to_string(),
            _ => mnem.to_string(),
        };
        let mut mnem_holder: Option<&'static str> = None;
        match op2 {
            0x40..=0x4f => mnem_holder = Some(CMOV[op2 as usize - 0x40]),
            0x90..=0x9f => mnem_holder = Some(SETCC[op2 as usize - 0x90]),
            _ => {}
        }
        let mut target = None;
        let mut rip_0f = None;
        let mut ops = String::new();

        if matches!(op2, 0x80..=0x8f) {
            // Jcc rel32 (concrete mnemonic from the CC nibble)
            mnem_holder = Some(cc_mnemonic(op2 & 0x0f));
            if p + 4 > end {
                return (
                    self.db(data, start, base_off),
                    Some("truncated jcc32".into()),
                );
            }
            let rel = i32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as i64;
            let next_v = self.vaddr_of(base_off + (p + 4) as u64);
            target = Some((next_v as i64 + rel) as u64);
            ops = format!("{:#x}", target.unwrap());
            p += 4;
            imm = 0; // the rel32 was consumed above; do not add imm again
        } else if has_modrm {
            let (m, rs, reg, rd, stopped) = self.eat_modrm(data, p, end, rex, opsize);
            if let Some(r) = stopped {
                return (self.db(data, start, base_off), Some(r));
            }
            p += m;
            // 0F 71..73 shifts: the reg digit selects the operation
            // (/2 psrl, /4 psra, /6 psll; 73 /3 psrldq, 73 /7 pslldq)
            // 0F 18 /0..3: prefetchnta/t0/t1/t2 by reg digit
            if op2 == 0x18 {
                mnem_holder = Some(match reg & 7 {
                    0 => "prefetchnta",
                    1 => "prefetcht0",
                    2 => "prefetcht1",
                    3 => "prefetcht2",
                    d => {
                        let _ = d;
                        "nop"
                    }
                });
            }
            if matches!(op2, 0x71 | 0x72 | 0x73) && mnem_holder.is_none() {
                let width = match op2 {
                    0x71 => 'w',
                    0x72 => 'd',
                    _ => 'q',
                };
                mnem_holder = Some(match (op2, reg & 7) {
                    (0x73, 3) => "psrldq",
                    (0x73, 7) => "pslldq",
                    (_, 2) => match width {
                        'w' => "psrlw",
                        'd' => "psrld",
                        _ => "psrlq",
                    },
                    (_, 4) => match width {
                        'w' => "psraw",
                        'd' => "psrad",
                        _ => "psrad",
                    },
                    (_, 6) => match width {
                        'w' => "psllw",
                        'd' => "pslld",
                        _ => "psllq",
                    },
                    (_, d) => {
                        return (
                            self.db(data, start, base_off),
                            Some(format!("bad 0f7x digit {d}").into()),
                        )
                    }
                });
            }
            // "reg, rm" order for the common two-operand 0F forms
            let regn = if matches!(op2, 0xb6 | 0xb7 | 0xbe | 0xbf) {
                // movzx/movsx: destination is a GPR, never xmm
                reg_name_sized(reg, opsize, self.bits64, rex & 8 != 0)
            } else {
                xmm_or_gpr(reg, rex)
            };
            let no_ops = matches!(op2, 0x1e | 0x18 | 0x19 | 0x1a | 0x1b)
                || (op2 == 0x1f && mnem_holder.is_none());
            ops = if no_ops {
                String::new()
            } else if matches!(
                op2,
                0x10..=0x17 | 0x28 | 0x29 | 0x2a..=0x2f | 0x40..=0x4f | 0x51 | 0x54..=0x5f
                    | 0x6e | 0x6f | 0x7e | 0x7f | 0xaf | 0xb6 | 0xb7 | 0xbe | 0xbf
                    | 0xbc..=0xbf | 0xd6
            ) {
                format!("{regn}, {rs}")
            } else {
                rs.clone()
            };
            if let Some(d) = rd {
                // RIP-relative (x86-64) / absolute [disp32] (i386) resolution
                let insn_va = self.vaddr_of(base_off + start as u64);
                let total = p + imm - start;
                let effective = if self.bits64 {
                    (insn_va as i64 + total as i64 + d) as u64
                } else {
                    d as u64
                };
                let note = match self.annotate(effective) {
                    Some(s) => format!(" = {effective:#x} {s}"),
                    None => format!(" = {effective:#x}"),
                };
                ops = format!("{ops}{note}");
                rip_0f = Some(effective);
            }
        }
        if p + imm > end {
            return (
                self.db(data, start, base_off),
                Some("truncated 0f imm".into()),
            );
        }
        let mut mnemonic = if let Some(m) = mnem_holder {
            m.to_string()
        } else if mnem_owned.is_empty() {
            format!("op_0f_{op2:02x}")
        } else {
            mnem_owned
        };
        if lock {
            mnemonic = format!("lock {mnemonic}");
        }
        let total = p + imm - start;
        if start + total > end {
            return (self.db(data, start, base_off), Some("0f overrun".into()));
        }
        let conf = classify_confidence(&mnemonic);
        (
            Insn {
                addr: self.vaddr_of(base_off + start as u64),
                offset: base_off + start as u64,
                len: total,
                bytes: data[start..start + total].to_vec(),
                mnemonic,
                operands: ops,
                target,
                rip_target: rip_0f,
                target_symbol: target
                    .and_then(|t| self.annotate(t))
                    .or_else(|| rip_0f.and_then(|r| self.annotate(r))),
                kind: kind.as_str(),
                confidence: conf,
            },
            None,
        )
    }

    /// Decode a VEX-encoded instruction (AVX/AVX2).
    /// `p` points at the C4/C5 byte. For C5, `b2` is the full payload byte
    /// (map is implied 0F); for C4, `b12` carries (byte1, byte2).
    #[allow(clippy::too_many_arguments)]
    fn decode_vex(
        &self,
        data: &[u8],
        start: usize,
        p: usize,
        end: usize,
        base_off: u64,
        payload: u8,
        b12: Option<(u8, u8)>,
    ) -> (Insn, Option<String>) {
        // C5 payload: R=~b7, vvvv=b6..b3, L=b2, pp=b1..b0
        // C4 b1: R=~b7, X=~b6, B=~b5, map_select=b4..b0
        // C4 b2: W=b7, vvvv=b6..b3, L=b2, pp=b1..b0
        let (map, w, l, pp, rex) = match b12 {
            None => {
                let mut r = 0u8;
                if payload & 0x80 == 0 {
                    r |= 0x04; // R
                }
                (0x0fu16, false, payload & 0x04 != 0, payload & 0x03, r)
            }
            Some((b1, b2)) => {
                let msel = b1 & 0x1f;
                let map = match msel {
                    1 => 0x0fu16,
                    2 => 0x0f38u16,
                    3 => 0x0f3au16,
                    8 => 0x08u16, // XOP (AMD)
                    9 => 0x09u16,
                    10 => 0x0au16,
                    _ => return (self.db(data, start, base_off), Some("bad vex map".into())),
                };
                let mut r = 0u8;
                if b1 & 0x80 == 0 {
                    r |= 0x04;
                } // R
                if b1 & 0x40 == 0 {
                    r |= 0x02;
                } // X
                if b1 & 0x20 == 0 {
                    r |= 0x01;
                } // B
                if b2 & 0x80 != 0 {
                    r |= 0x08;
                } // W
                (map, b2 & 0x80 != 0, b2 & 0x04 != 0, b2 & 0x03, r)
            }
        };
        let _ = l; // L selects xmm/ymm; naming uses ymm for AVX2-capable paths
        let prefix_len = if b12.is_some() { 3 } else { 2 };
        let op = p + prefix_len;
        if op >= end {
            return (
                self.db(data, start, base_off),
                Some("vex truncated opcode".into()),
            );
        }
        let opcode = data[op];
        let (mnem, kind, imm_extra, has_modrm) = vex_mnemonic(map, opcode, pp, w, l);
        let mut mnem: &'static str = mnem;
        if !has_modrm {
            // e.g. vzeroupper (C5 F8 77): opcode only
            let total = op + 1 - start;
            if start + total > end {
                return (self.db(data, start, base_off), Some("vex overrun".into()));
            }
            return (
                Insn {
                    addr: self.vaddr_of(base_off + start as u64),
                    offset: base_off + start as u64,
                    len: total,
                    bytes: data[start..start + total].to_vec(),
                    mnemonic: mnem.to_string(),
                    operands: String::new(),
                    target: None,
                    rip_target: None,
                    target_symbol: None,
                    kind: kind.as_str(),
                    confidence: classify_confidence(mnem),
                },
                None,
            );
        }
        let opsize = false;
        let (m, rm, reg, _rd, stopped) = self.eat_modrm(data, op + 1, end, rex, opsize);
        if let Some(r) = stopped {
            return (self.db(data, start, base_off), Some(r));
        }
        // VEX 71/72/73 (vpsrl/vpsra/vpsll by imm8): the reg digit selects the
        // operation (/2 psrl, /4 psra, /6 psll), width letter by opcode row
        if map == 0x0f && matches!(opcode, 0x71 | 0x72 | 0x73) {
            let width = match opcode {
                0x71 => 'w',
                0x72 => 'd',
                _ => 'q',
            };
            mnem = match reg & 7 {
                2 => match width {
                    'q' => "vpsrlq",
                    'd' => "vpsrld",
                    _ => "vpsrlw",
                },
                4 => match width {
                    'd' => "vpsrad",
                    _ => "vpsraw",
                },
                6 => match width {
                    'q' => "vpsllq",
                    'd' => "vpslld",
                    _ => "vpsllw",
                },
                _ => mnem,
            };
        }
        let total = op + 1 + m + imm_extra - start;
        if start + total > end {
            return (self.db(data, start, base_off), Some("vex overrun".into()));
        }
        // operand sketch: vector register for reg field + rm operand
        let reg_v = vec_name(reg, pp, w);
        let ops = if rm.starts_with('[') || rm.is_empty() {
            format!("{reg_v}, {rm}")
        } else {
            let rm_v = vec_from_gpr(&rm, pp, w);
            format!("{reg_v}, {rm_v}")
        };
        (
            Insn {
                addr: self.vaddr_of(base_off + start as u64),
                offset: base_off + start as u64,
                len: total,
                bytes: data[start..start + total].to_vec(),
                mnemonic: mnem.to_string(),
                operands: ops,
                target: None,
                rip_target: None,
                target_symbol: None,
                kind: kind.as_str(),
                confidence: classify_confidence(mnem),
            },
            None,
        )
    }

    /// Decode an EVEX-encoded instruction (AVX-512). Length-only decoding plus
    /// generic mnemonic: EVEX is 4 bytes, then opcode, then ModRM.
    fn decode_evex(
        &self,
        data: &[u8],
        start: usize,
        p: usize,
        end: usize,
        base_off: u64,
        b: (u8, u8, u8),
    ) -> (Insn, Option<String>) {
        let (b1, b2, b3) = b;
        // EVEX byte1: R X B R' 0 m m m  -> map = b1 & 0x07
        let map = match b1 & 0x07 {
            1 => 0x0f,
            2 => 0x0f38,
            3 => 0x0f3a,
            _ => return (self.db(data, start, base_off), Some("bad evex map".into())),
        };
        let op = p + 4;
        if op >= end {
            return (
                self.db(data, start, base_off),
                Some("evex truncated opcode".into()),
            );
        }
        let w = b2 & 0x80 != 0;
        let pp = b3 & 0x03;
        // EVEX LL bits (b3 bits 5-6): 00=128, 01=256, 10=512 — nonzero means
        // the vector width is at least 256, which vzeroall-style naming uses
        let l = (b3 & 0x20) != 0;
        let (mnem, kind, imm_extra, has_modrm) = vex_mnemonic(map, data[op], pp, w, l);
        // R/X/B: b1 bits 7/6/5 (inverted); bit4 is R' (extends reg high bit),
        // which does not affect ModRM register numbering below 16.
        let mut rex = 0u8;
        if b1 & 0x80 == 0 {
            rex |= 0x04;
        }
        if b1 & 0x40 == 0 {
            rex |= 0x02;
        }
        if b1 & 0x20 == 0 {
            rex |= 0x01;
        }
        if w {
            rex |= 0x08;
        }
        rex &= 0x07; // W not used by eat_modrm
        if !has_modrm {
            let total = op + 1 + imm_extra - start;
            if start + total > end {
                return (self.db(data, start, base_off), Some("evex overrun".into()));
            }
            return (
                Insn {
                    addr: self.vaddr_of(base_off + start as u64),
                    offset: base_off + start as u64,
                    len: total,
                    bytes: data[start..start + total].to_vec(),
                    mnemonic: mnem.to_string(),
                    operands: String::new(),
                    target: None,
                    rip_target: None,
                    target_symbol: None,
                    kind: kind.as_str(),
                    confidence: classify_confidence(mnem),
                },
                None,
            );
        }
        let opsize = false;
        let (m, rm, reg, _rd, stopped) = self.eat_modrm(data, op + 1, end, rex, opsize);
        if let Some(r) = stopped {
            return (self.db(data, start, base_off), Some(r));
        }
        // EVEX may carry a compressed displacement (disp8*N) — same byte count
        // as regular disp8, so the length computation is unchanged.
        let total = op + 1 + m + imm_extra - start;
        if start + total > end {
            return (self.db(data, start, base_off), Some("evex overrun".into()));
        }
        let reg_v = evex_reg(reg, b2, b3);
        let ops = if rm.starts_with('[') || rm.is_empty() {
            format!("{reg_v}, {rm}")
        } else {
            let rm_v = evex_reg_from_str(&rm, b2, b3);
            format!("{reg_v}, {rm_v}")
        };
        (
            Insn {
                addr: self.vaddr_of(base_off + start as u64),
                offset: base_off + start as u64,
                len: total,
                bytes: data[start..start + total].to_vec(),
                mnemonic: mnem.to_string(),
                operands: ops,
                target: None,
                rip_target: None,
                target_symbol: None,
                kind: kind.as_str(),
                confidence: classify_confidence(mnem),
            },
            None,
        )
    }

    /// Consume ModRM (+SIB+disp). Returns (len, rm_operand, reg_field, abs_addr, stop).
    /// `abs_addr` carries either a RIP-relative displacement (x86-64) or the
    /// absolute [disp32] address (i386) so callers can resolve the target.
    fn eat_modrm(
        &self,
        data: &[u8],
        p: usize,
        end: usize,
        rex: u8,
        opsize: bool,
    ) -> (usize, String, u8, Option<i64>, Option<String>) {
        if p >= end {
            return (0, String::new(), 0, None, Some("truncated at modrm".into()));
        }
        let m = data[p];
        let modbits = m >> 6;
        let reg = ((m >> 3) & 7) + if rex & 4 != 0 { 8 } else { 0 };
        let rm_raw = m & 7;
        let rexb = if rex & 1 != 0 { 8u8 } else { 0u8 };
        let mut len = 1usize;

        if modbits == 3 {
            let rm = rm_raw + rexb;
            let name = reg_name_sized(rm, opsize, self.bits64, rex & 8 != 0);
            return (len, name, reg, None, None);
        }

        // SIB byte (both 32- and 64-bit modes when rm == 100)
        if rm_raw == 4 {
            if p + 1 >= end {
                return (0, String::new(), 0, None, Some("truncated at sib".into()));
            }
            let sib = data[p + 1];
            len += 1;
            let scale = 1u64 << (sib >> 6);
            let index = ((sib >> 3) & 7) + if rex & 2 != 0 { 8 } else { 0 };
            let base_raw = sib & 7;
            let base = base_raw + rexb;
            let mut parts: Vec<String> = Vec::new();
            if index != 4 {
                parts.push(format!("{}*{scale}", reg64_name(index, self.bits64)));
            }
            if modbits == 0 && base_raw == 5 && rexb == 0 {
                // [disp32] with no base
                if p + 5 >= end {
                    return (
                        0,
                        String::new(),
                        0,
                        None,
                        Some("truncated sib disp32".into()),
                    );
                }
                let disp = u32::from_le_bytes(data[p + 2..p + 6].try_into().unwrap()) as i64;
                return (6, format!("[{:#x}]", disp), reg, Some(disp), None);
            }
            let base_name = reg64_name(base, self.bits64).to_string();
            if parts.is_empty() {
                parts.push(base_name);
            } else {
                parts.push(format!("+{base_name}"));
            }
            match modbits {
                1 => {
                    if p + 2 >= end {
                        return (0, String::new(), 0, None, Some("truncated disp8".into()));
                    }
                    let d = data[p + 2] as i8;
                    if d != 0 {
                        parts.push(format!("{d:+#x}"));
                    }
                    len += 1;
                }
                2 => {
                    if p + 5 >= end {
                        return (0, String::new(), 0, None, Some("truncated disp32".into()));
                    }
                    let d = i32::from_le_bytes(data[p + 2..p + 6].try_into().unwrap());
                    if d != 0 {
                        parts.push(format!("{d:+#x}"));
                    }
                    len += 4;
                }
                _ => {}
            }
            return (len, format!("[{}]", parts.join("")), reg, None, None);
        }

        // no SIB
        if modbits == 0 && rm_raw == 5 && rexb == 0 {
            if p + 4 >= end {
                return (
                    0,
                    String::new(),
                    0,
                    None,
                    Some("truncated disp32/rip".into()),
                );
            }
            let disp = i32::from_le_bytes(data[p + 1..p + 5].try_into().unwrap()) as i64;
            if self.bits64 {
                return (5, format!("[rip{disp:+#x}]"), reg, Some(disp), None);
            }
            // i386: [disp32] is an absolute address — expose it as the target
            return (5, format!("[{:#x}]", disp), reg, Some(disp), None);
        }
        let rm = rm_raw + rexb;
        let mut s = format!("[{}]", reg64_name(rm, self.bits64));
        match modbits {
            1 => {
                if p + 1 >= end {
                    return (0, String::new(), 0, None, Some("truncated disp8".into()));
                }
                let d = data[p + 1] as i8;
                if d != 0 {
                    s = format!("[{}{d:+#x}]", reg64_name(rm, self.bits64));
                }
                len += 1;
            }
            2 => {
                if p + 4 >= end {
                    return (0, String::new(), 0, None, Some("truncated disp32".into()));
                }
                let d = i32::from_le_bytes(data[p + 1..p + 5].try_into().unwrap());
                if d != 0 {
                    s = format!("[{}{d:+#x}]", reg64_name(rm, self.bits64));
                }
                len += 4;
            }
            _ => {}
        }
        (len, s, reg, None, None)
    }

    fn db(&self, data: &[u8], start: usize, base_off: u64) -> Insn {
        let l = (start + 1).min(data.len()) - start;
        Insn {
            addr: self.vaddr_of(base_off + start as u64),
            offset: base_off + start as u64,
            len: l,
            bytes: data[start..start + l].to_vec(),
            mnemonic: "db".to_string(),
            operands: format!("{:#04x}", data[start]),
            target: None,
            rip_target: None,
            target_symbol: None,
            kind: OpKind::Data.as_str(),
            confidence: "low",
        }
    }
}

fn reg64_name(reg: u8, bits64: bool) -> &'static str {
    const Q: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    const D: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    if bits64 {
        Q[reg as usize]
    } else {
        D[reg as usize]
    }
}

/// reg field name with explicit REX.W awareness (reg field already includes
/// REX.R; REX.W selects 64- vs 32-bit width unless 66 selects 16-bit).
///
/// Byte-wide names (al/cl/...) are only correct for genuinely 8-bit operand
/// forms; the default (no 66, no REX.W) operand width is 32-bit in both
/// i386 and x86-64 modes, so the 32-bit table is the right default.
fn reg_name_sized(reg: u8, opsize: bool, bits64: bool, rex_w: bool) -> String {
    if opsize {
        const W: [&str; 16] = [
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
            "r13w", "r14w", "r15w",
        ];
        W[reg as usize].to_string()
    } else if bits64 {
        if rex_w {
            reg64_name(reg, true).to_string()
        } else {
            const D: [&str; 16] = [
                "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d",
                "r11d", "r12d", "r13d", "r14d", "r15d",
            ];
            D[reg as usize].to_string()
        }
    } else {
        // i386 mode, default operand size: 32-bit GPRs
        const D32: [&str; 16] = [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eax", "ecx", "edx", "ebx",
            "esp", "ebp", "esi", "edi",
        ];
        D32[reg as usize].to_string()
    }
}

fn reg_name(reg: u8, opsize: bool, bits64: bool) -> &'static str {
    const W: [&str; 16] = [
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w",
        "r13w", "r14w", "r15w",
    ];
    const D32: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eax", "ecx", "edx", "ebx", "esp",
        "ebp", "esi", "edi",
    ];
    if opsize {
        W[reg as usize]
    } else if bits64 {
        reg64_name(reg, true)
    } else {
        // i386: default operand size is 32-bit GPRs
        D32[reg as usize]
    }
}

/// SSE/SSE2 register or GPR name for the 0F map reg field.
fn xmm_or_gpr(reg: u8, _rex: u8) -> String {
    if reg < 16 {
        format!("xmm{reg}")
    } else {
        format!("r{reg}")
    }
}

fn imm_sz(opsize: bool) -> usize {
    if opsize {
        2
    } else {
        4
    }
}

/// x87 FPU opcode names: rows D8..DF, columns ModRM reg field (0..7).
/// Empty string = rare/uniform form, falls back to "fpu".
const FPU_TABLE: [[&str; 8]; 8] = [
    // D8: FADD FMUL FCOM FCOMP FSUB FSUBR FDIV FDIVR
    [
        "fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr",
    ],
    // D9: FLD FXCH FNOP FSTP (reg 3) + special forms
    ["fld", "fxch", "fnop", "fstp", "", "", "", ""],
    // DA: FIADD FIMUL FICOM FICOMP FISUB FISUBR FIDIV FIDIVR
    [
        "fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr",
    ],
    // DB: FILD FISTTP FIST FISTP / FLD m80 (reg5) / FSTP m80 (reg7)
    ["fild", "fisttp", "fist", "fistp", "", "fld", "", "fstp"],
    // DC: FADD FMUL FCOM FCOMP FSUB FSUBR FDIV FDIVR (m64fp)
    [
        "fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr",
    ],
    // DD: FLD FISTTP FST FSTP FRSTOR / FSAVE FSTSW
    [
        "fld", "fisttp", "fst", "fstp", "frstor", "", "fsave", "fstsw",
    ],
    // DE: FADDP FMULP FCOMPP FSUBP FSUBRP FDIVP FDIVRP
    [
        "faddp", "fmulp", "fcompp", "fsubp", "fsubrp", "fdivp", "fdivrp", "",
    ],
    // DF: FILD FISTTP FIST FISTP FBLD FILD64 FBSTP FISTP64
    [
        "fild", "fisttp", "fist", "fistp", "fbld", "fild", "fbstp", "fistp",
    ],
];

fn fpu_mnemonic(op: u8, reg: u8, rm: u8, reg_form: bool) -> &'static str {
    if reg_form {
        // mod=3: register-form tables differ from the memory-form rows
        let name = fpu_reg_mnemonic(op, reg, rm);
        return if name.is_empty() { "fpu" } else { name };
    }
    let name = FPU_TABLE[(op - 0xd8) as usize][(reg & 7) as usize];
    if name.is_empty() {
        "fpu"
    } else {
        name
    }
}

/// x87 register-form (mod=3) mnemonics: rows D8..DF keyed by the ModRM reg
/// field, with the rm field selecting st(i) — except the one-byte specials
/// where only a single encoding is valid (FNOP at D9 D0, FUCOMPP at DA E9,
/// FCOMPP at DE D9, FNSTSW AX at DF E0) and the D9 constant clusters
/// (FCHS/FLD1/F2XM1/FPREM rows) keyed purely by rm.
/// Empty string = invalid/reserved encoding (caller falls back to "fpu").

/// REX.W bit set (widens operands to 64 bits).
fn rex_w_set(rex: u8) -> bool {
    rex & 0x08 != 0
}

/// Confidence classification for a decoded row:
///   "low"    — db data bytes and synthetic placeholder names
///   "medium" — family sketches with a slash or dash (movlp/unpck, ins/outs,
///              vpsrlw/vpslld..., "fpu", ...) where the name is approximate
///   "high"   — everything else (concrete table names)
fn confidence_counts(insns: &[Insn]) -> (usize, usize, usize) {
    let mut c = (0, 0, 0);
    for i in insns {
        match i.confidence {
            "high" => c.0 += 1,
            "medium" => c.1 += 1,
            _ => c.2 += 1,
        }
    }
    c
}

pub fn classify_confidence(mnemonic: &str) -> &'static str {
    if mnemonic == "db"
        || mnemonic.starts_with("op_0f_")
        || mnemonic.starts_with("vex_")
        || mnemonic.starts_with("xop")
        || mnemonic == "fpu"
        || mnemonic == "sse"
        || mnemonic == "grp1"
        || mnemonic == "grp2"
        || mnemonic == "grp3"
        || mnemonic == "grp4/5"
        || mnemonic == "grp8"
        || mnemonic == "grp_ps"
    {
        "low"
    } else if mnemonic.contains('/') || mnemonic.contains("vex_") {
        "medium"
    } else {
        "high"
    }
}

/// Register name (eax..r15d) -> 0..15 index for width rewrites.
fn rm_str_to_index(rm: &str) -> usize {
    const D: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    for (i, n) in D.iter().enumerate() {
        if rm == *n {
            return i;
        }
    }
    0
}

/// Sized string-op suffix: b for byte forms, w with 66, d by default,
/// q only when REX.W widens the operand (A5 without REX.W is movsd, not movsq).
fn string_suffix(op: u8, opsize: bool, bits64: bool, rex: u8) -> String {
    if op & 1 == 0 {
        "b".to_string()
    } else if opsize {
        "w".to_string()
    } else if bits64 && rex_w_set(rex) {
        "q".to_string()
    } else {
        "d".to_string()
    }
}

/// Recover the raw ModRM rm field (0..7) from a reg-form operand string
/// ("eax".."edi" in i386, "eax".."r15d" in x64). The reg-form x87 tables key
/// specials off this index; for non-reg operands return 0.
fn x87_rm_index(rm_str: &str) -> u8 {
    const GPRS: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    for (i, g) in GPRS.iter().enumerate() {
        if rm_str == *g {
            return i as u8;
        }
    }
    0
}

fn fpu_reg_mnemonic(op: u8, reg: u8, rm: u8) -> &'static str {
    let r = reg & 7;
    let i = rm & 7;
    match (op, r, i) {
        // single-byte specials
        (0xd9, 2, 0) => "fnop",
        (0xda, 5, 1) => "fucompp",
        (0xde, 3, 1) => "fcompp",
        (0xdf, 4, 0) => "fnstsw",
        _ => match op {
            // st(i),st / st,st(i) arithmetic: same names as the memory table
            // D8 reg-form matches the memory table names; DC reg-form
            // SWAPS sub<->subr and div<->divr (SDM: DC E0+i = FSUBR ST(i),ST;
            // E8+i = FSUB; F0+i = FDIVR; F8+i = FDIV)
            0xd8 => FPU_TABLE[0][r as usize],
            0xdc => match r {
                0 => "fadd",
                1 => "fmul",
                4 => "fsubr",
                5 => "fsub",
                6 => "fdivr",
                7 => "fdiv",
                _ => "",
            },
            0xd9 => match r {
                0 => "fld",
                1 => "fxch",
                4 => ["fchs", "fabs", "", "", "ftst", "fxam", "", ""][i as usize],
                5 => [
                    "fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", "",
                ][i as usize],
                6 => [
                    "f2xm1", "fyl2x", "fptan", "fpatan", "", "", "fdecstp", "fincstp",
                ][i as usize],
                7 => [
                    "fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos",
                ][i as usize],
                _ => "",
            },
            0xda => match r {
                0 => "fcmovb",
                1 => "fcmove",
                2 => "fcmovbe",
                3 => "fcmovu",
                _ => "",
            },
            0xdb => match r {
                0 => "fcmovnb",
                1 => "fcmovne",
                2 => "fcmovnbe",
                3 => "fcmovnu",
                5 => "fucomi",
                6 => "fucomip",
                _ => "",
            },
            0xdd => match r {
                0 => "ffree",
                2 => "fst",
                3 => "fstp",
                4 => "fucom",
                5 => "fucomp",
                _ => "",
            },
            0xde => match r {
                0 => "faddp",
                1 => "fmulp",
                4 => "fsubrp",
                5 => "fsubp",
                6 => "fdivrp",
                7 => "fdivp",
                _ => "",
            },
            0xdf => match r {
                0 => "ffreep",
                5 => "fucompi",
                6 => "fcompi",
                _ => "",
            },
            _ => "",
        },
    }
}

/// Concrete cmovcc mnemonics (0F 40..4F).
const CMOV: [&str; 16] = [
    "cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova", "cmovs", "cmovns",
    "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
];

/// Concrete setcc mnemonics (0F 90..9F).
const SETCC: [&str; 16] = [
    "seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta", "sets", "setns", "setp",
    "setnp", "setl", "setge", "setle", "setg",
];

/// CC condition table (opcode low nibble / 0F second byte - 0x80).
const CC: [&str; 16] = [
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge",
    "jle", "jg",
];

fn cc_mnemonic(cc: u8) -> &'static str {
    CC[(cc & 0x0f) as usize]
}

/// one-byte opcode -> (mnemonic, kind, has_modrm, imm_len)
fn one_byte(
    op: u8,
    rep: u8,
    opsize: bool,
    rex: u8,
    bits64: bool,
) -> (&'static str, OpKind, bool, usize) {
    match op {
        0x00..=0x03 => ("add", OpKind::Arith, true, 0),
        0x04 => ("add", OpKind::Arith, false, 1),
        0x05 => ("add", OpKind::Arith, false, imm_sz(opsize)),
        0x06 | 0x0e | 0x16 | 0x1e => ("push", OpKind::Push, false, 0),
        0x07 | 0x17 | 0x1f => ("pop", OpKind::Pop, false, 0),
        0x08..=0x0b => ("or", OpKind::Logic, true, 0),
        0x0c => ("or", OpKind::Logic, false, 1),
        0x0d => ("or", OpKind::Logic, false, imm_sz(opsize)),
        0x10..=0x13 => ("adc", OpKind::Arith, true, 0),
        0x14 => ("adc", OpKind::Arith, false, 1),
        0x15 => ("adc", OpKind::Arith, false, imm_sz(opsize)),
        0x18..=0x1b => ("sbb", OpKind::Arith, true, 0),
        0x1c => ("sbb", OpKind::Arith, false, 1),
        0x1d => ("sbb", OpKind::Arith, false, imm_sz(opsize)),
        0x20..=0x23 => ("and", OpKind::Logic, true, 0),
        0x24 => ("and", OpKind::Logic, false, 1),
        0x25 => ("and", OpKind::Logic, false, imm_sz(opsize)),
        0x27 => ("daa", OpKind::Other, false, 0),
        0x2f => ("das", OpKind::Other, false, 0),
        0x37 => ("aaa", OpKind::Other, false, 0),
        0x3f => ("aas", OpKind::Other, false, 0),
        0x28..=0x2b => ("sub", OpKind::Arith, true, 0),
        0x2c => ("sub", OpKind::Arith, false, 1),
        0x2d => ("sub", OpKind::Arith, false, imm_sz(opsize)),
        0x30..=0x33 => ("xor", OpKind::Logic, true, 0),
        0x34 => ("xor", OpKind::Logic, false, 1),
        0x35 => ("xor", OpKind::Logic, false, imm_sz(opsize)),
        0x38..=0x3b => ("cmp", OpKind::Cmp, true, 0),
        0x3c => ("cmp", OpKind::Cmp, false, 1),
        0x3d => ("cmp", OpKind::Cmp, false, imm_sz(opsize)),
        0x40..=0x47 if !bits64 => ("inc", OpKind::Arith, false, 0),
        0x48..=0x4f if !bits64 => ("dec", OpKind::Arith, false, 0),
        0x50..=0x57 => ("push", OpKind::Push, false, 0),
        0x58..=0x5f => ("pop", OpKind::Pop, false, 0),
        0x60 | 0x61 if !bits64 => (
            if op == 0x60 { "pusha" } else { "popa" },
            OpKind::Other,
            false,
            0,
        ),
        0x63 if bits64 => ("movsxd", OpKind::Mov, true, 0),
        0x63 if !bits64 => ("arpl", OpKind::Logic, true, 0), // i286 legacy, i386 PE
        0x68 => ("push", OpKind::Push, false, imm_sz(opsize)),
        0x69 => ("imul", OpKind::Arith, true, imm_sz(opsize)),
        0x6a => ("push", OpKind::Push, false, 1),
        0x6b => ("imul", OpKind::Arith, true, 1),
        0x6c => ("insb", OpKind::String, false, 0),
        0x6d => ("insd", OpKind::String, false, 0),
        0x6e => ("outsb", OpKind::String, false, 0),
        0x6f => ("outsd", OpKind::String, false, 0),
        0x70..=0x7f => ("jcc", OpKind::Jcc, false, 1),
        0x80..=0x83 => (
            "grp1",
            OpKind::Arith,
            true,
            if op == 0x81 { imm_sz(opsize) } else { 1 },
        ),
        0x84 | 0x85 => ("test", OpKind::Test, true, 0),
        0x86 | 0x87 => ("xchg", OpKind::Xchg, true, 0),
        0x88..=0x8b => ("mov", OpKind::Mov, true, 0),
        0x8c | 0x8e => ("mov", OpKind::Mov, true, 0),
        0x8d => ("lea", OpKind::Lea, true, 0),
        0x8f => ("pop", OpKind::Pop, true, 0),
        0x90 => (
            "nop",
            if rep != 0 {
                OpKind::String
            } else {
                OpKind::Nop
            },
            false,
            0,
        ),
        0x91..=0x97 => ("xchg", OpKind::Xchg, false, 0),
        0x98 => (
            // cwde/cdq family: concrete name picked in decode_one by mode+66
            "cwde/cdq",
            OpKind::Other,
            false,
            0,
        ),
        0x99 => ("cdq", OpKind::Other, false, 0), // cqo in 64-bit w/o 66
        0x9a if !bits64 => ("callf", OpKind::Call, false, 6),
        0x9b => ("fwait", OpKind::Other, false, 0),
        0x9c => (
            if bits64 { "pushfq" } else { "pushfd" },
            OpKind::Push,
            false,
            0,
        ),
        0x9d => (
            if bits64 { "popfq" } else { "popfd" },
            OpKind::Pop,
            false,
            0,
        ),
        0x9e => ("sahf", OpKind::Other, false, 0),
        0x9f => ("lahf", OpKind::Other, false, 0),
        0xa0..=0xa3 => (
            "mov",
            OpKind::Mov,
            false,
            // 66 сужает РЕГИСТР (ax), но moffs-адрес остаётся 32-битным
            // в i386 (objdump: `66 a3 92 a6 7d 00` = mov ds:0x7da692, ax);
            // только REX.W расширяет и адрес до 64 бит в x86-64.
            if bits64 && rex & 8 != 0 {
                8
            } else if bits64 && opsize {
                2
            } else {
                4
            },
        ),
        0xa4..=0xa7 => ("movs", OpKind::String, false, 0), // refined below
        0xa8 => ("test", OpKind::Test, false, 1),
        0xa9 => ("test", OpKind::Test, false, imm_sz(opsize)),
        0xaa..=0xaf => ("stos/lods/scas", OpKind::String, false, 0),
        0xb0..=0xb7 => ("mov", OpKind::Mov, false, 1),
        0xb8..=0xbf => (
            "mov",
            OpKind::Mov,
            false,
            if bits64 && rex & 8 != 0 {
                8
            } else {
                imm_sz(opsize)
            },
        ),
        0xc0 | 0xc1 => ("grp2", OpKind::Shift, true, 1),
        0xc2 => ("ret", OpKind::Ret, false, 2),
        0xc3 => ("ret", OpKind::Ret, false, 0),
        // CA/CB retf (+imm16); C4/C5 lds/les в 32-бит режиме (в 64-бит это
        // VEX и разбирается раньше, в префиксах); D6 salc
        0xca => ("retf", OpKind::Ret, false, 2),
        0xcb => ("retf", OpKind::Ret, false, 0),
        0xc4 | 0xc5 if !bits64 => ("lds/les", OpKind::Mov, true, 0),
        0xc6 => ("mov", OpKind::Mov, true, 1),
        0xc7 => ("mov", OpKind::Mov, true, imm_sz(opsize)),
        0xc8 => ("enter", OpKind::Other, false, 3),
        0xc9 => ("leave", OpKind::Other, false, 0),
        0xcc => ("int3", OpKind::Int, false, 0),
        0xcd => ("int", OpKind::Int, false, 1),
        0xce => ("into", OpKind::Int, false, 0),
        0xcf => ("iretd", OpKind::Ret, false, 0),
        0xd0..=0xd3 => ("grp2", OpKind::Shift, true, 0),
        0xd4 => ("aam", OpKind::Other, false, 1),
        0xd5 => ("aad", OpKind::Other, false, 1),
        0xd6 => ("salc", OpKind::Other, false, 0),
        0xd7 => ("xlatb", OpKind::Other, false, 0),
        0xd8..=0xdf => ("fpu", OpKind::Other, true, 0),
        0xe0 => ("loopne", OpKind::Jcc, false, 1),
        0xe1 => ("loope", OpKind::Jcc, false, 1),
        0xe2 => ("loop", OpKind::Jcc, false, 1),
        0xe3 => (
            if bits64 { "jrcxz" } else { "jecxz" },
            OpKind::Jcc,
            false,
            1,
        ),
        // E4-E7 in/out с imm8-портом (2 байта; EC-EF — DX-форма)
        0xe4 | 0xe5 => ("in", OpKind::Privileged, false, 1),
        0xe6 | 0xe7 => ("out", OpKind::Privileged, false, 1),
        0xe8 => ("call", OpKind::Call, false, 4),
        0xe9 => ("jmp", OpKind::Jmp, false, 4),
        0xea if !bits64 => ("jmpf", OpKind::Jmp, false, 6),
        0xeb => ("jmp", OpKind::Jmp, false, 1),
        0xec | 0xed => ("in", OpKind::Privileged, false, 0),
        0xee | 0xef => ("out", OpKind::Privileged, false, 0),
        0xf1 => ("int1", OpKind::Int, false, 0),
        0xf4 => ("hlt", OpKind::Privileged, false, 0),
        0xf5 => ("cmc", OpKind::Other, false, 0),
        0xf6 | 0xf7 => (
            "grp3",
            OpKind::Logic,
            true,
            if op == 0xf7 { imm_sz(opsize) } else { 1 },
        ),
        0xf8 => ("clc", OpKind::Other, false, 0),
        0xf9 => ("stc", OpKind::Other, false, 0),
        0xfa => ("cli", OpKind::Privileged, false, 0),
        0xfb => ("sti", OpKind::Privileged, false, 0),
        0xfc => ("cld", OpKind::Other, false, 0),
        0xfd => ("std", OpKind::Other, false, 0),
        0xfe | 0xff => ("grp4/5", OpKind::Other, true, 0),
        _ => ("db", OpKind::Data, false, 0),
    }
}

/// VEX/EVEX opcode map: enough mnemonics to be useful, correct lengths always.
/// Returns (mnemonic, kind, extra_imm_bytes, has_modrm).
fn vex_mnemonic(
    map: u16,
    opcode: u8,
    pp: u8,
    w: bool,
    l: bool,
) -> (&'static str, OpKind, usize, bool) {
    // pp: 0=none, 1=66, 2=F3, 3=F2 — selects scalar/packed variant names
    if map == 0x0f {
        match opcode {
            // VEX.128.0F.77 = vzeroupper (L=0); VEX.256.0F.77 = vzeroall (L=1)
            0x77 => (
                if l { "vzeroall" } else { "vzeroupper" },
                OpKind::Other,
                0,
                false,
            ),
            0x10 | 0x11 => {
                let m = match (pp, w) {
                    (0, false) => "vmovups",
                    (1, false) => "vmovupd",
                    (2, false) => "vmovss",
                    (3, false) => "vmovsd",
                    (0, true) => "vmovups",
                    (1, true) => "vmovupd",
                    _ => "vmovs",
                };
                (m, OpKind::Mov, 0, true)
            }
            0x12..=0x17 => ("vmovlp/unpck", OpKind::Mov, 0, true),
            0x28 | 0x29 => (
                if pp == 1 { "vmovapd" } else { "vmovaps" },
                OpKind::Mov,
                0,
                true,
            ),
            0x2c | 0x2d => ("vcvtts2si", OpKind::Mov, 0, true),
            0x2e | 0x2f => ("vucomis", OpKind::Cmp, 0, true),
            0x40..=0x4f => ("vcmovcc", OpKind::Mov, 0, true),
            0x50 => ("vmovmsk", OpKind::Mov, 0, true),
            0x51 => ("vsqrts", OpKind::Arith, 0, true),
            0x54..=0x57 => (
                match opcode {
                    0x54 => "vandp",
                    0x55 => "vandnp",
                    0x56 => "vorp",
                    _ => "vxorp",
                },
                OpKind::Logic,
                0,
                true,
            ),
            0x58..=0x5f => (
                match opcode {
                    0x58 => {
                        if pp == 1 {
                            "vaddpd"
                        } else {
                            "vaddps"
                        }
                    }
                    0x59 => {
                        if pp == 1 {
                            "vmulpd"
                        } else {
                            "vmulps"
                        }
                    }
                    0x5c => {
                        if pp == 1 {
                            "vsubpd"
                        } else {
                            "vsubps"
                        }
                    }
                    0x5e => {
                        if pp == 1 {
                            "vdivpd"
                        } else {
                            "vdivps"
                        }
                    }
                    _ => "vfma",
                },
                OpKind::Arith,
                0,
                true,
            ),
            0x6c | 0x6d => ("vpunpcklqdq/vpunpckhqdq", OpKind::Mov, 0, true),
            0x6e => ("vmovd", OpKind::Mov, 0, true),
            0x6f => (
                match pp {
                    1 => "vmovdqa",
                    2 => "vmovdqu",
                    _ => "vmovdqa",
                },
                OpKind::Mov,
                0,
                true,
            ),
            0x7c => ("vhaddpd", OpKind::Arith, 0, true),
            0x7d => ("vhsubpd", OpKind::Arith, 0, true),
            0x7e => ("vmovd", OpKind::Mov, 0, true),
            0x7f => (
                match pp {
                    1 => "vmovdqa",
                    2 => "vmovdqu",
                    _ => "vmovdqa",
                },
                OpKind::Mov,
                0,
                true,
            ),
            0x70 => (
                match pp {
                    1 => "vpshufd",
                    2 => "vpshufhw",
                    3 => "vpshuflw",
                    _ => "vpshufw",
                },
                OpKind::Mov,
                1,
                true,
            ),
            0x71..=0x73 => ("vpsrlw/vpslld/vpsllq", OpKind::Shift, 1, true),
            0x74 => ("vpcmpeqb", OpKind::Logic, 0, true),
            0x75 => ("vpcmpeqw", OpKind::Logic, 0, true),
            0x76 => ("vpcmpeqd", OpKind::Logic, 0, true),
            0x38 | 0x39 => ("vpabs", OpKind::Arith, 0, true),
            0x62 => ("vpunpckldq", OpKind::Mov, 0, true),
            0x63 => ("vpacksswb", OpKind::Mov, 0, true),
            0x64 => ("vpcmpgtb", OpKind::Logic, 0, true),
            0x65 => ("vpcmpgtw", OpKind::Logic, 0, true),
            0x66 => ("vpcmpgtd", OpKind::Logic, 0, true),
            0x67 => ("vpackuswb", OpKind::Mov, 0, true),
            0x68 => ("vpunpckhbw", OpKind::Mov, 0, true),
            0x69 => ("vpunpckhwd", OpKind::Mov, 0, true),
            0x6a => ("vpunpckhdq", OpKind::Mov, 0, true),
            0x6b => ("vpackssdw", OpKind::Mov, 0, true),
            0x6c => ("vpunpcklqdq", OpKind::Mov, 0, true),
            0x6d => ("vpunpckhqdq", OpKind::Mov, 0, true),
            0x7a..=0x7f => ("vpbroadcast/vpermt2b", OpKind::Mov, 0, true),
            0x80..=0x8f => ("vkand/kmov/kunpck", OpKind::Logic, 0, true),
            0x90 => ("kmovw", OpKind::Mov, 0, true),
            0x91 => ("kmovq", OpKind::Mov, 0, true),
            0x92 => ("kmovb", OpKind::Mov, 0, true),
            0x93 => ("kmovd", OpKind::Mov, 0, true),
            0x94..=0x97 => ("vkmov/vpscatter", OpKind::Mov, 0, true),
            0x98..=0x9f => ("vkortest/vpconflict", OpKind::Logic, 0, true),
            0xa2..=0xa5 => ("vpbroadcastb/w/vcompress", OpKind::Mov, 0, true),
            0xb4..=0xb7 => ("vpmadd52/vshufi32x4", OpKind::Arith, 1, true),
            0xc2 => ("vcmpps", OpKind::Cmp, 1, true),
            0xc4 | 0xc5 => ("vpinsrw/vpextrw", OpKind::Mov, 1, true),
            0xc6 => ("vshufp/vshufi", OpKind::Mov, 1, true),
            0xcb | 0xcd => ("vpshufbitqmb/vpexpand", OpKind::Mov, 0, true),
            0xce | 0xcf => ("vgather/vpgather", OpKind::Mov, 0, true),
            0xd0..=0xd3 => ("vaddsub/vpsrlvw", OpKind::Arith, 0, true),
            0xd4 => ("vpadd", OpKind::Arith, 0, true),
            0xd5 => ("vpandd/vpaddq", OpKind::Logic, 0, true),
            0xd6 => ("vmovq", OpKind::Mov, 0, true),
            0xd7 => ("vpmovmskb", OpKind::Mov, 0, true),
            0xd8 => ("vpsubusb", OpKind::Arith, 0, true),
            0xd9 => ("vpsubusw", OpKind::Arith, 0, true),
            0xda => ("vpminub", OpKind::Arith, 0, true),
            0xdb => ("vpand", OpKind::Logic, 0, true),
            0xdc => ("vpaddusb", OpKind::Arith, 0, true),
            0xdd => ("vpaddusw", OpKind::Arith, 0, true),
            0xde => ("vpmaxub", OpKind::Arith, 0, true),
            0xdf => ("vpandn", OpKind::Logic, 0, true),
            0xe0 => ("vpavgb", OpKind::Arith, 0, true),
            0xe3 => ("vpavgw", OpKind::Arith, 0, true),
            0xe4 => ("vpmulhuw", OpKind::Arith, 0, true),
            0xe6 => ("vcvttps/vcvtdq", OpKind::Mov, 0, true),
            0xe7 => ("vmovd/vmovq", OpKind::Mov, 0, true),
            0xe8 => ("vpsubsb", OpKind::Arith, 0, true),
            0xe9 => ("vpsubsw", OpKind::Arith, 0, true),
            0xea => ("vpminsw", OpKind::Arith, 0, true),
            0xeb => ("vpor", OpKind::Logic, 0, true),
            0xec => ("vpaddsb", OpKind::Arith, 0, true),
            0xed => ("vpaddsw", OpKind::Arith, 0, true),
            0xee => ("vpmaxsw", OpKind::Arith, 0, true),
            0xef => ("vpxor", OpKind::Logic, 0, true),
            0xf0 | 0xf1 => ("vlddqu", OpKind::Mov, 0, true),
            0xf2 | 0xf3 => ("vpsll", OpKind::Shift, 0, true),
            0xf4 => ("vpmuludq", OpKind::Arith, 0, true),
            0xf5 => ("vpmaddwd", OpKind::Arith, 0, true),
            0xf6 => ("vpsadbw", OpKind::Arith, 0, true),
            0xf7 => ("vmaskmovdqu", OpKind::Mov, 0, true),
            0xf8 => ("vpsubb", OpKind::Arith, 0, true),
            0xf9 => ("vpsubw", OpKind::Arith, 0, true),
            0xfa => ("vpsubd", OpKind::Arith, 0, true),
            0xfb => ("vpsubq", OpKind::Arith, 0, true),
            0xfc => ("vpaddb", OpKind::Arith, 0, true),
            0xfd => ("vpaddw", OpKind::Arith, 0, true),
            _ => ("vex_0f", OpKind::Other, 0, true),
        }
    } else if map == 0x0f38 {
        match opcode {
            0x00..=0x0f => ("vpshufb/psign/etc", OpKind::Mov, 0, true),
            0x17 | 0x18 => ("vptest", OpKind::Test, 0, true),
            0x2a => ("vmovdqu8/16", OpKind::Mov, 0, true),
            0x2c..=0x2f => ("vmaskmov", OpKind::Mov, 0, true),
            // 0x40-0x4F on the 0F38 map are vpsrlv/vpsllv/vpblendmd etc: NO imm8
            0x40..=0x4f => ("vpsllv/psrlv/perm", OpKind::Shift, 0, true),
            0x58 => ("vpbroadcast", OpKind::Mov, 0, true),
            0x59 => ("vbroadcasti", OpKind::Mov, 0, true),
            0x78 | 0x79 => ("vpbroadcastb/w", OpKind::Mov, 0, true),
            0x8c => ("vpmaskmov", OpKind::Mov, 0, true),
            0x90..=0x97 => ("vpgather", OpKind::Mov, 0, true),
            0xf0 | 0xf1 => ("vmovdqu/movdqa", OpKind::Mov, 0, true),
            _ => ("vex_0f38", OpKind::Other, 0, true),
        }
    } else if map == 0x0f3a {
        match opcode {
            0x0e | 0x0f => ("vpblendvb/palignr", OpKind::Mov, 1, true),
            0x08 | 0x09 => ("vroundps/pd", OpKind::Arith, 1, true),
            0x0a | 0x0b => ("vroundss/sd", OpKind::Arith, 1, true),
            0x0c | 0x0d => ("vblendps/pd", OpKind::Mov, 1, true),
            0x14 | 0x15 => ("vpextrb/w", OpKind::Mov, 1, true),
            0x16 | 0x17 => ("vpextrd/q", OpKind::Mov, 1, true),
            0x20..=0x22 => ("vpinsrb/w/d", OpKind::Mov, 1, true),
            0x40 | 0x41 => ("vdpps/pd", OpKind::Arith, 1, true),
            0x4a..=0x4d => ("vvblend/vdpp", OpKind::Mov, 1, true),
            0x60..=0x6f => ("vpunpck/vperm", OpKind::Mov, 1, true),
            _ => ("vex_0f3a", OpKind::Other, 1, true),
        }
    } else if map == 0x08 || map == 0x09 || map == 0x0a {
        // XOP (AMD): map 8/9/10. Most rotate/shift ops carry imm8; vfrcz does not.
        match opcode {
            0x80..=0x83 => ("vfrcz", OpKind::Arith, 0, true),
            0x90..=0x97 => ("vprot/shl/shr", OpKind::Shift, 1, true),
            0x98..=0x9f => ("vrot/shl/shr imm", OpKind::Shift, 1, true),
            0xa0..=0xa3 => ("vpcmov/vpcomb", OpKind::Logic, 1, true),
            _ => ("xop", OpKind::Other, 1, true),
        }
    } else {
        ("vex", OpKind::Other, 0, true)
    }
}

/// Vector register name from a reg field index (ymm for AVX2-capable encodings).
fn vec_name(reg: u8, _pp: u8, _w: bool) -> String {
    if reg < 32 {
        format!("ymm{reg}")
    } else {
        format!("r{reg}")
    }
}

/// Re-label a GPR operand produced by eat_modrm as a vector register.
fn vec_from_gpr(rm: &str, pp: u8, w: bool) -> String {
    const GPRS: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    const GPRS32: [&str; 16] = [
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
        "r12d", "r13d", "r14d", "r15d",
    ];
    for (i, g) in GPRS.iter().enumerate() {
        if rm == *g {
            return vec_name(i as u8, pp, w);
        }
    }
    for (i, g) in GPRS32.iter().enumerate() {
        if rm == *g {
            return vec_name(i as u8, pp, w);
        }
    }
    rm.to_string()
}

/// EVEX register name (zmm unless the LL bits select 128/256-bit).
fn evex_reg(reg: u8, b2: u8, b3: u8) -> String {
    // LL bits are b2 bits 6..7? In EVEX b2 is the third byte: [W:1][vvvv:4][1][pp:2]
    // LL actually lives in b3 bits 5..6. Keep it simple: zmm naming.
    let _ = (b2, b3);
    if reg < 32 {
        format!("zmm{reg}")
    } else {
        format!("r{reg}")
    }
}

fn evex_reg_from_str(rm: &str, b2: u8, b3: u8) -> String {
    const GPRS: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    for (i, g) in GPRS.iter().enumerate() {
        if rm == *g {
            return evex_reg(i as u8, b2, b3);
        }
    }
    rm.to_string()
}
/// Common SSSE3/SSE4/SSE4a rows of the 0F38/0F3A three-byte maps. Opcodes
/// outside the table keep the generic `op_0f_3x_yy` placeholder — lengths are
/// always correct; the name is only a sketch for rare rows.
fn three_byte_mnemonic(op2: u8, op3: u8, digit: u8) -> String {
    if op2 == 0x38 {
        match op3 {
            0x00 => "pshufb".into(),
            0x01 => "phaddw".into(),
            0x02 => "phaddd".into(),
            0x03 => "phaddsw".into(),
            0x04 => "pmaddubsw".into(),
            0x05 => "phsubw".into(),
            0x06 => "phsubd".into(),
            0x07 => "phsubsw".into(),
            0x08 => "psignb".into(),
            0x09 => "psignw".into(),
            0x0a => "psignd".into(),
            0x0b => "pmulhrsw".into(),
            0x10 => "pblendvb".into(),
            0x14 => "blendvps".into(),
            0x15 => "blendvpd".into(),
            0x17 => "ptest".into(),
            0x1c => "pabsb".into(),
            0x1d => "pabsw".into(),
            0x1e => "pabsd".into(),
            0x20 => "pmovsxbw".into(),
            0x21 => "pmovsxbd".into(),
            0x22 => "pmovsxbq".into(),
            0x23 => "pmovsxwd".into(),
            0x24 => "pmovsxwq".into(),
            0x25 => "pmovsxdq".into(),
            0x28 => "pmuldq".into(),
            0x29 => "pcmpeqb".into(),
            0x2a => "movdqa/movdqu".into(),
            0x2b => "packusdw".into(),
            0x30 => "pmovzxbw".into(),
            0x31 => "pmovzxbd".into(),
            0x32 => "pmovzxbq".into(),
            0x33 => "pmovzxwd".into(),
            0x34 => "pmovzxwq".into(),
            0x35 => "pmovzxdq".into(),
            0x37 => "pcmpgtq".into(),
            0x38 => "pmovsxbw/minps".into(),
            0x3a => "pminsb".into(),
            0x3b => "pminsd".into(),
            0x3c => "pminuw".into(),
            0x3d => "pminud".into(),
            0x3e => "pmaxsb".into(),
            0x3f => "pmaxuw".into(),
            0x40 => "pmulld".into(),
            0x41 => "phminposuw".into(),
            0x80..=0x8f => "invept/invvpid".into(),
            0xdb => "aesimc".into(),
            0xdc => "aesenc".into(),
            0xdd => "aesenclast".into(),
            0xde => "aesdec".into(),
            0xdf => "aesdeclast".into(),
            0xf0 => "movbe/crc32".into(),
            0xf1 => {
                if digit == 0 {
                    "crc32".into()
                } else {
                    "crc32".into()
                }
            }
            _ => format!("op_0f_{op2:02x}_{op3:02x}"),
        }
    } else {
        // 0F 3A
        match op3 {
            0x0b => "roundps".into(),
            0x0c => "roundss".into(),
            0x0e => "pblendw".into(),
            0x0f => "palignr".into(),
            0x14 => "pextrb".into(),
            0x15 => "pextrw/pextrd".into(),
            0x16 => "pextrq/pextrd".into(),
            0x20 => "pinsrb".into(),
            0x21 => "insertps".into(),
            0x22 => "pinsrd/pinsrq".into(),
            0x40 => "dpps".into(),
            0x41 => "dppd".into(),
            0x60 => "pcmpestrm".into(),
            0x61 => "pcmpestri".into(),
            0x62 => "pcmpistrm".into(),
            0x63 => "pcmpistri".into(),
            _ => format!("op_0f_{op2:02x}_{op3:02x}"),
        }
    }
}

/// 0F map: (mnemonic, kind, has_modrm, imm_len)
fn map0f(op2: u8, rep: u8, _opsize: bool) -> (&'static str, OpKind, bool, usize) {
    match op2 {
        0x05 => ("syscall", OpKind::Syscall, false, 0),
        0x06 | 0x07 => ("clts/sysret", OpKind::Privileged, false, 0),
        0x0b => ("ud2", OpKind::Other, false, 0),
        0x10 | 0x11 => (
            if rep == 0xf3 {
                "movss"
            } else if rep == 0xf2 {
                "movsd"
            } else {
                "movups"
            },
            OpKind::Mov,
            true,
            0,
        ),
        0x12..=0x17 => ("movlp/unpck", OpKind::Mov, true, 0),
        0x18 => ("prefetch", OpKind::Other, true, 0), // digit-named in decode_0f
        0x1e => (
            if rep == 0xf3 { "endbr64" } else { "nop" },
            OpKind::Nop,
            true,
            0,
        ),
        0x1f => ("nop", OpKind::Nop, true, 0),
        0x20..=0x25 => ("mov", OpKind::Mov, true, 0),
        0x28 | 0x29 => ("movaps", OpKind::Mov, true, 0),
        // 2A/2C/2D: MMX (no prefix) vs SSE (F3=ss / F2=sd) forms
        0x2a => (
            if rep == 0xf3 {
                "cvtsi2ss"
            } else if rep == 0xf2 {
                "cvtsi2sd"
            } else if _opsize {
                "cvtpi2pd"
            } else {
                "cvtpi2ps"
            },
            OpKind::Mov,
            true,
            0,
        ),
        0x2c | 0x2d => (
            if rep == 0xf3 {
                "cvttss2si"
            } else if rep == 0xf2 {
                "cvttsd2si"
            } else {
                "cvtts2si"
            },
            OpKind::Mov,
            true,
            0,
        ),
        0x2b => ("movntps/movntdq", OpKind::Mov, true, 0),
        0x2e | 0x2f => ("ucomis", OpKind::Cmp, true, 0),
        0x30 | 0x32 | 0x33 => ("wrmsr/rdmsr", OpKind::Privileged, false, 0),
        0x31 => ("rdtsc", OpKind::Privileged, false, 0),
        0x34 | 0x35 => ("sysenter/sysexit", OpKind::Syscall, false, 0),
        0x40..=0x4f => ("cmovcc", OpKind::Mov, true, 0),
        0x50 => ("movmskps", OpKind::Mov, true, 0),
        0x51 => ("sqrtps", OpKind::Arith, true, 0),
        0x54 => ("andps", OpKind::Logic, true, 0),
        0x55 => ("andnps", OpKind::Logic, true, 0),
        0x56 => ("orps", OpKind::Logic, true, 0),
        0x57 => ("xorps", OpKind::Logic, true, 0),
        0x58..=0x5f => ("add/sub/mul/div-s", OpKind::Arith, true, 0),
        0x60 => ("punpcklbw", OpKind::Mov, true, 0),
        0x61 => ("punpcklwd", OpKind::Mov, true, 0),
        0x62 => ("punpckldq", OpKind::Mov, true, 0),
        0x63 => ("packsswb", OpKind::Mov, true, 0),
        0x64 => ("pcmpgtb", OpKind::Logic, true, 0),
        0x65 => ("pcmpgtw", OpKind::Logic, true, 0),
        0x66 => ("pcmpgtd", OpKind::Logic, true, 0),
        0x67 => ("packuswb", OpKind::Mov, true, 0),
        0x68 => ("punpckhbw", OpKind::Mov, true, 0),
        0x69 => ("punpckhwd", OpKind::Mov, true, 0),
        0x6a => ("punpckhdq", OpKind::Mov, true, 0),
        0x6b => ("packssdw", OpKind::Mov, true, 0),
        0x6c => ("punpcklqdq", OpKind::Mov, true, 0),
        0x6d => ("punpckhqdq", OpKind::Mov, true, 0),
        0x6e | 0x7e => ("movd", OpKind::Mov, true, 0),
        0x6f | 0x7f => (
            if rep == 0xf3 {
                "movdqu"
            } else if _opsize {
                "movdqa"
            } else {
                "movq" // MMX form (66-less): movq mm, mm/m64
            },
            OpKind::Mov,
            true,
            0,
        ),
        0x70 => (
            match (rep, _opsize) {
                (0xf3, _) => "pshufhw",
                (0xf2, _) => "pshuflw",
                (_, true) => "pshufd",
                _ => "pshufw",
            },
            OpKind::Mov,
            true,
            1,
        ),
        0x71..=0x73 => ("grp_ps", OpKind::Shift, true, 1),
        0x74 => ("pcmpeqb", OpKind::Logic, true, 0),
        0x75 => ("pcmpeqw", OpKind::Logic, true, 0),
        0x76 => ("pcmpeqd", OpKind::Logic, true, 0),
        0x77 => ("emms", OpKind::Other, false, 0),
        0x80..=0x8f => ("jcc", OpKind::Jcc, false, 4),
        0x90..=0x9f => ("setcc", OpKind::Other, true, 0),
        0xa0 => ("push fs", OpKind::Push, false, 0),
        0xa1 => ("pop fs", OpKind::Pop, false, 0),
        0xa2 => ("cpuid", OpKind::Privileged, false, 0),
        0xa3 => ("bt", OpKind::Logic, true, 0),
        0xa4 => ("shld", OpKind::Shift, true, 1), // shld r/m, r, imm8
        0xa5 => ("shld", OpKind::Shift, true, 0), // shld r/m, r, cl
        0xac => ("shrd", OpKind::Shift, true, 1), // shrd r/m, r, imm8
        0xad => ("shrd", OpKind::Shift, true, 0), // shrd r/m, r, cl
        0xa6 | 0xa7 | 0xb0 | 0xb1 => ("cmpxchg", OpKind::Logic, true, 0),
        0xa8 => ("push gs", OpKind::Push, false, 0),
        0xa9 => ("pop gs", OpKind::Pop, false, 0),
        0xaa => ("rsm", OpKind::Privileged, false, 0),
        0xaf => ("imul", OpKind::Arith, true, 0),
        0xb3 | 0xbb => ("btr/btc", OpKind::Logic, true, 0),
        0xb6 | 0xb7 => ("movzx", OpKind::Mov, true, 0),
        0xba => ("grp8", OpKind::Logic, true, 1),
        0xbc | 0xbd => (
            if rep == 0xf3 {
                if op2 == 0xbc {
                    "tzcnt"
                } else {
                    "lzcnt"
                }
            } else if op2 == 0xbc {
                "bsf"
            } else {
                "bsr"
            },
            OpKind::Logic,
            true,
            0,
        ),
        0xbe | 0xbf => ("movsx", OpKind::Mov, true, 0),
        0xc0 | 0xc1 => ("xadd", OpKind::Arith, true, 0),
        0xc2 => ("cmpps", OpKind::Cmp, true, 1),
        0xc3 => ("movnti", OpKind::Mov, true, 0),
        0xc4 => ("pinsrw", OpKind::Mov, true, 1),
        0xc5 => ("pextrw", OpKind::Mov, true, 1),
        0xc6 => ("shufps", OpKind::Mov, true, 1),
        0xc7 => ("cmpxchg8b", OpKind::Logic, true, 0),
        0xc8..=0xcf => ("bswap", OpKind::Other, false, 0),
        0xd4 => ("paddq", OpKind::Arith, true, 0),
        0xd7 => ("pmovmskb", OpKind::Mov, true, 0),
        0xd8 => ("psubb", OpKind::Arith, true, 0),
        0xd9 => ("psubw", OpKind::Arith, true, 0),
        0xda => ("psubd", OpKind::Arith, true, 0),
        0xdb => ("pand", OpKind::Logic, true, 0),
        0xdc => ("paddb", OpKind::Arith, true, 0),
        0xdd => ("paddw", OpKind::Arith, true, 0),
        0xde => ("paddd", OpKind::Arith, true, 0),
        0xef => ("pxor", OpKind::Logic, true, 0),
        0xf8 => ("psubb", OpKind::Arith, true, 0),
        0xf9 => ("psubw", OpKind::Arith, true, 0),
        0xfa => ("psubd", OpKind::Arith, true, 0),
        0xfb => ("psubq", OpKind::Arith, true, 0),
        0xfc => ("paddb", OpKind::Arith, true, 0),
        0xfd => ("paddw", OpKind::Arith, true, 0),
        0xfe => ("paddd", OpKind::Arith, true, 0),
        0xe0 => ("pavgb", OpKind::Arith, true, 0),
        0xe3 => ("pavgw", OpKind::Arith, true, 0),
        0xe4 => ("pmulhuw", OpKind::Arith, true, 0),
        0xd5 => ("pmullw", OpKind::Arith, true, 0),
        0xea => ("pminsw", OpKind::Arith, true, 0),
        0xeb => ("por", OpKind::Logic, true, 0),
        0xdf => ("pandn", OpKind::Logic, true, 0),
        0xec => ("paddsb", OpKind::Arith, true, 0),
        0xed => ("paddsw", OpKind::Arith, true, 0),
        0xee => ("pmaxsw", OpKind::Arith, true, 0),
        0xf0 => ("movbe/lddqu", OpKind::Mov, true, 0),
        0xf2 => ("pslldq", OpKind::Shift, true, 0),
        0xf3 => ("psllq", OpKind::Shift, true, 0),
        0xf4 => ("pmuludq", OpKind::Arith, true, 0),
        0xf5 => ("pmaddwd", OpKind::Arith, true, 0),
        0xf6 => ("psadbw", OpKind::Arith, true, 0),
        0xfe => ("paddd", OpKind::Arith, true, 0),
        0xd0..=0xff => ("sse", OpKind::Other, true, 0),
        _ => ("", OpKind::Other, true, 0),
    }
}
