// Модуль `tests` внутри tests.rs — стандартная схема встроенных тестов cargo
// (имя модуля совпадает с файлом, отсюда allow module_inception).
#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::core::Binary;
    use crate::sha256::sha256;

    fn test_elf() -> Option<Binary> {
        for p in ["/bin/true", "/bin/ls", "/usr/bin/env"] {
            if let Ok(b) = Binary::load(p) {
                return Some(b);
            }
        }
        None
    }

    /// Build a tiny valid ELF64 with a single .text section containing `code`.
    /// Layout: ELF header (64) + section data (code) + section name string table
    /// + 3 section headers (null, .text, .shstrtab).
    fn tiny_elf64(code: &[u8]) -> Binary {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // 64-bit
        buf[5] = 1; // LE
        buf[6] = 1; // version
        buf[7] = 0; // sysv
                    // e_type EXEC
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine x86-64
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry = 0x1000
        buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        // e_shoff filled later
        // e_ehsize
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_shentsize
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());

        // section data at offset 0x100, vaddr 0x1000
        let data_off: u64 = 0x100;
        let data_len = code.len() as u64;
        // shstrtab after data
        let shstr: &[u8] = b"\0.text\0.shstrtab\0";
        let shstr_off = data_off + data_len;
        // section headers after shstrtab
        let shoff = (shstr_off + shstr.len() as u64 + 7) & !7u64;

        buf.extend(std::iter::repeat_n(0u8, (data_off - 64) as usize));
        buf.extend_from_slice(code);
        buf.extend_from_slice(shstr);
        // pad to shoff
        while buf.len() < shoff as usize {
            buf.push(0);
        }
        // shoff
        buf[40..48].copy_from_slice(&shoff.to_le_bytes());
        // e_shnum = 3
        buf[60..62].copy_from_slice(&3u16.to_le_bytes());
        // e_shstrndx = 2
        buf[62..64].copy_from_slice(&2u16.to_le_bytes());

        // section headers: null, .text, .shstrtab
        let mut sh = vec![0u8; 64]; // null
                                    // .text: name@1 (".text" offset in shstr), type PROGBITS, flags AX,
                                    // addr 0x1000, offset data_off, size data_len
        let mut text = vec![0u8; 64];
        text[0..4].copy_from_slice(&1u32.to_le_bytes()); // sh_name -> "\0.text": name at +1
        text[4..8].copy_from_slice(&1u32.to_le_bytes()); // PROGBITS
        text[8..16].copy_from_slice(&0x6u64.to_le_bytes()); // SHF_ALLOC|SHF_EXECINSTR
        text[16..24].copy_from_slice(&0x1000u64.to_le_bytes()); // addr
        text[24..32].copy_from_slice(&data_off.to_le_bytes());
        text[32..40].copy_from_slice(&data_len.to_le_bytes());
        sh.extend_from_slice(&text);
        // .shstrtab: name at 7, type SHT_STRTAB(3)
        let mut sst = vec![0u8; 64];
        sst[0..4].copy_from_slice(&7u32.to_le_bytes());
        sst[4..8].copy_from_slice(&3u32.to_le_bytes());
        sst[24..32].copy_from_slice(&shstr_off.to_le_bytes());
        sst[32..40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());
        sh.extend_from_slice(&sst);

        buf.extend_from_slice(&sh);
        Binary::from_data(buf, "tiny.elf").unwrap()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(crate::core::shannon_entropy(&[]), 0.0);
        assert_eq!(crate::core::shannon_entropy(&[b'a'; 1000]), 0.0);
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((crate::core::shannon_entropy(&data) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn tiny_elf_is_valid() {
        let bin = tiny_elf64(&[0x90, 0x90, 0xc3]);
        assert_eq!(bin.format, crate::core::Format::Elf);
        assert!(bin.is_64());
        assert_eq!(bin.entry(), 0x1000);
        let secs = bin.sections();
        assert_eq!(secs.len(), 3);
        assert_eq!(secs[1].name, ".text");
        // vaddr<->offset mapping
        assert_eq!(bin.vaddr_to_offset(0x1000).unwrap(), 0x100);
        assert_eq!(bin.offset_to_vaddr(0x100).unwrap(), 0x1000);
        // read via vaddr
        assert_eq!(bin.read_vaddr(0x1000, 3).unwrap(), &[0x90, 0x90, 0xc3]);
    }

    #[test]
    fn parse_system_elf() {
        let bin = match test_elf() {
            Some(b) => b,
            None => return,
        };
        assert_eq!(bin.format, crate::core::Format::Elf);
        assert!(!bin.sections().is_empty());
        let text = bin.sections().iter().find(|s| s.name == ".text").unwrap();
        let off = bin.vaddr_to_offset(text.vaddr).unwrap();
        assert_eq!(off, text.offset);
        let va = bin.offset_to_vaddr(text.offset).unwrap();
        assert_eq!(va, text.vaddr);
        let e = bin.entry();
        bin.vaddr_to_offset(e).expect("entry must be mapped");
    }

    #[test]
    fn disasm_entry_and_mapping() {
        let bin = match test_elf() {
            Some(b) => b,
            None => return,
        };
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_vaddr(bin.entry(), 64).unwrap();
        assert!(!d.insns.is_empty());
        for i in &d.insns {
            assert!(i.len >= 1 && i.len <= 15);
            assert!(i.addr >= bin.entry());
        }
        for w in d.insns.windows(2) {
            assert_eq!(w[0].addr + w[0].len as u64, w[1].addr);
        }
    }

    #[test]
    fn disasm_known_bytes() {
        let code = [
            0x48, 0x89, 0xd1, // mov rcx, rdx
            0x31, 0xc0, // xor eax, eax
            0xeb, 0x02, // jmp +2
            0x90, 0x90, 0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xc3, // ret
        ];
        let bin = tiny_elf64(&code);
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_vaddr(0x1000, 14).unwrap();
        let mnems: Vec<&str> = d.insns.iter().map(|i| i.mnemonic.as_str()).collect();
        assert_eq!(
            mnems,
            vec!["mov", "xor", "jmp", "nop", "nop", "endbr64", "ret"]
        );
        let lens: Vec<usize> = d.insns.iter().map(|i| i.len).collect();
        assert_eq!(lens, vec![3, 2, 2, 1, 1, 4, 1]);
        // jmp at 0x1005, next insn 0x1007, rel 2 -> 0x1009 (endbr64, skips nops)
        assert_eq!(d.insns[2].target, Some(0x1009));
        // addresses are VAs
        assert_eq!(d.insns[0].addr, 0x1000);
        assert_eq!(d.insns[5].addr, 0x1009);
        assert_eq!(d.insns[6].addr, 0x100d);
    }

    #[test]
    fn disasm_call_rel32_target() {
        // e8 rel32: call 0x1000+5+5
        let code = [0xe8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90];
        let bin = tiny_elf64(&code);
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_vaddr(0x1000, 10).unwrap();
        assert_eq!(d.insns[0].mnemonic, "call");
        assert_eq!(d.insns[0].target, Some(0x100a));
    }

    #[test]
    fn disasm_rip_relative() {
        // 48 8b 05 xx xx xx xx: mov rax, [rip+0] -> reads next 8 bytes at 0x1007
        let code = [0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb];
        let bin = tiny_elf64(&code);
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_vaddr(0x1000, 7).unwrap();
        let i = &d.insns[0];
        assert_eq!(i.mnemonic, "mov");
        assert_eq!(i.len, 7);
        assert!(i.operands.contains("= 0x1007"), "operands: {}", i.operands);
    }

    #[test]
    fn patch_bytes_parser() {
        assert_eq!(
            crate::cmd_mod::parse_patch_bytes("\\x90\\x90\\xeb").unwrap(),
            vec![0x90, 0x90, 0xeb]
        );
        assert_eq!(
            crate::cmd_mod::parse_patch_bytes("AB\\nC").unwrap(),
            vec![b'A', b'B', b'\n', b'C']
        );
        assert!(crate::cmd_mod::parse_patch_bytes("").is_err());
        assert!(crate::cmd_mod::parse_patch_bytes("\\x9").is_err());
    }

    #[test]
    fn pe_dll_exports() {
        // fixture generated by scripts/make_pe_fixture.py (AddOne, Another);
        // regenerate it here so the test is self-contained on a fresh machine
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../make_pe_fixture.py");
        if std::path::Path::new(script).exists() {
            let _ = std::process::Command::new("python3").arg(script).output();
        }
        if let Ok(bin) = Binary::load("/tmp/pe_dll.dll") {
            assert_eq!(bin.format, crate::core::Format::Pe);
            assert!(bin.is_64());
            let exps = bin.exports();
            assert!(exps.iter().any(|e| e.name == "AddOne"), "exports: {exps:?}");
            assert!(exps.iter().any(|e| e.name == "Another"));
            assert!(exps.iter().all(|e| e.addr != 0), "exports: {exps:?}");
        }
    }

    #[test]
    fn strings_on_elf() {
        let bin = match test_elf() {
            Some(b) => b,
            None => return,
        };
        // strings() требует минимум 2
        let out = crate::cmd_analyze::strings(&bin, 8, "GLIBC", None, false, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("GLIBC_"), "got: {text}");
    }

    // ---------- regression tests: vector prefixes & misc decodes ----------

    fn decode_first(code: &[u8]) -> crate::disasm::Insn {
        let bin = tiny_elf64(code);
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_offset(0x100, code.len().max(16));
        d.insns[0].clone()
    }

    #[test]
    fn vex2_length_and_mnemonic() {
        // c5 f8 77 = vzeroupper (no ModRM)
        let i = decode_first(&[0xc5, 0xf8, 0x77]);
        assert_eq!(i.len, 3, "vzeroupper must be 3 bytes");
        assert_eq!(i.mnemonic, "vzeroupper");
        // c5 fa 10 c1 = vmovss xmm0, xmm1 (ModRM c1, mod=3)
        let i = decode_first(&[0xc5, 0xfa, 0x10, 0xc1]);
        assert_eq!(i.len, 4);
        assert!(i.mnemonic.starts_with("vmov"), "got {}", i.mnemonic);
    }

    #[test]
    fn vex3_length_maps() {
        // c4 e1 f9 7e c0 = vmovq rax, xmm0 (map 0F, W=1)
        let i = decode_first(&[0xc4, 0xe1, 0xf9, 0x7e, 0xc0]);
        assert_eq!(i.len, 5);
        // c4 e2 71 0f e0 08 = vpalignr with imm8 (map 0F3A)
        let i = decode_first(&[0xc4, 0xe3, 0x71, 0x0f, 0xe0, 0x08]);
        assert_eq!(i.len, 6, "vpalignr carries imm8");
        // c4 e2 7d 58 db = vpbroadcastd (map 0F38, no imm)
        let i = decode_first(&[0xc4, 0xe2, 0x7d, 0x58, 0xdb]);
        assert_eq!(i.len, 5);
    }

    #[test]
    fn evex_length_and_map() {
        // 62 f1 fd 48 d4 c1 = vpaddq zmm1, zmm0, zmm0 (map 0F via b1&7==1)
        let i = decode_first(&[0x62, 0xf1, 0xfd, 0x48, 0xd4, 0xc1]);
        assert_eq!(i.len, 6);
        assert!(i.mnemonic.contains("vpadd"), "got {}", i.mnemonic);
        // 62 e1 fd 20 db 05 <disp32> = vpandq ymm16, [rip+disp32] — 10 bytes
        let code = [0x62, 0xe1, 0xfd, 0x20, 0xdb, 0x05, 0x6d, 0xbf, 0x34, 0x00];
        let i = decode_first(&code);
        assert_eq!(i.len, 10, "EVEX rip-relative disp32 must be consumed");
        assert!(i.operands.contains("rip"), "got {}", i.operands);
    }

    #[test]
    fn xop_prefix_decoded() {
        // 8f e8 78 c2 ec 0e = XOP vprotd xmm5, xmm4, imm8 (6 bytes)
        let i = decode_first(&[0x8f, 0xe8, 0x78, 0xc2, 0xec, 0x0e]);
        assert_eq!(i.len, 6, "XOP rotate carries imm8");
    }

    #[test]
    fn fwait_glued_to_fpu() {
        // 9b d9 7c 24 fa = fstcw -0x6(%rsp): objdump-style glue, 5 bytes total
        let i = decode_first(&[0x9b, 0xd9, 0x7c, 0x24, 0xfa]);
        assert_eq!(i.len, 5, "fwait must glue to the x87 insn like objdump");
    }

    #[test]
    fn shrd_cl_form_no_imm() {
        // 0f ad da = shrd edx, ebx, cl — 3 bytes, NO imm8
        let i = decode_first(&[0x0f, 0xad, 0xda]);
        assert_eq!(i.len, 3);
        // 0f ac d0 08 = shrd al, dl... imm8 form — 4 bytes
        let i = decode_first(&[0x0f, 0xac, 0xd0, 0x08]);
        assert_eq!(i.len, 4);
    }

    #[test]
    fn pinsrw_pextrw_imm() {
        // 66 0f c5 f8 00 = pextrw edi, xmm0, 0 — 5 bytes with imm8
        let i = decode_first(&[0x66, 0x0f, 0xc5, 0xf8, 0x00]);
        assert_eq!(i.len, 5);
        // 66 0f c4 c7 01 = pinsrw xmm0, edi, 1 — 5 bytes
        let i = decode_first(&[0x66, 0x0f, 0xc4, 0xc7, 0x01]);
        assert_eq!(i.len, 5);
    }

    #[test]
    fn addr32_prefix_before_vex() {
        // 67 c4 61 f9 7e e8 = addr32 vmovq — prefix 67 then VEX, 6 bytes
        let i = decode_first(&[0x67, 0xc4, 0x61, 0xf9, 0x7e, 0xe8]);
        assert_eq!(i.len, 6, "67 before VEX must be consumed as a prefix");
    }

    #[test]
    fn disasm_count_zero_rejected() {
        let bin = match test_elf() {
            Some(b) => b,
            None => return,
        };
        assert!(crate::cmd_analyze::disasm(&bin, "0", 0, None, false, false).is_err());
        // window cap
        assert!(
            crate::cmd_analyze::disasm(&bin, "0", 10, Some(0xffff_ffff), false, false).is_err()
        );
    }

    // ---------- new-feature tests: search / xrefs / utf16 / until-ret / hashes ----------

    #[test]
    fn search_pattern_parse() {
        use crate::cmd_search::parse_pattern;
        assert_eq!(
            parse_pattern("\\xe8\\x90\\x90\\x90\\x90").unwrap(),
            vec![Some(0xe8), Some(0x90), Some(0x90), Some(0x90), Some(0x90)]
        );
        // wildcards
        assert_eq!(
            parse_pattern("\\xe8??\\xff").unwrap(),
            vec![Some(0xe8), None, Some(0xff)]
        );
        assert_eq!(
            parse_pattern("AB..C").unwrap(),
            vec![Some(b'A'), Some(b'B'), None, Some(b'C')]
        );
        assert!(parse_pattern("").is_err());
        assert!(parse_pattern("\\x9").is_err()); // truncated escape
        assert!(parse_pattern("ab\\qz").is_err()); // unsupported escape
        assert!(parse_pattern("aé").is_err()); // non-ascii
    }

    #[test]
    fn search_find_all() {
        // exercised through the public API on a tiny ELF: pattern present once
        let mut code = vec![0x48, 0x89, 0xe5, 0x90, 0x90, 0x90, 0xc3];
        let bin = tiny_elf64(&code);
        let out = crate::cmd_search::search(&bin, "\\x90\\x90\\x90", 10, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("matches: 1"), "got: {text}");
        // wildcard: ?? matches any byte between two fixed bytes
        let out = crate::cmd_search::search(&bin, "\\x89??\\x90", 10, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("matches: 1"), "got: {text}");
        // not found
        let out = crate::cmd_search::search(&bin, "\\xde\\xad\\xbe\\xef", 10, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("matches: 0"), "got: {text}");
        // max cap
        let out = crate::cmd_search::search(&bin, "\\x90", 2, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("matches: 3"), "got: {text}");
        assert!(text.contains("showing first 2"), "got: {text}");
        code.clear();
        let _ = code;
    }

    #[test]
    fn xrefs_call_target() {
        // code at vaddr 0x1000:
        //   0x1000: e8 24 00 00 00  call rel32 -> next(0x1005)+0x24 = 0x1029
        //   0x1005..0x1018: nops (20 bytes)
        //   0x1019: eb 0e          jmp rel8 -> next(0x101b)+0x0e = 0x1029
        //   0x101b..0x1028: nops (14 bytes)
        //   0x1029: c3             ret
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&[0xe8, 0x24, 0x00, 0x00, 0x00]); // call 0x1029
        code.extend(std::iter::repeat_n(0x90u8, 20)); // 0x1005..0x1018
        code.extend_from_slice(&[0xeb, 0x0e]); // 0x1019: jmp 0x1029
        code.extend(std::iter::repeat_n(0x90u8, 14)); // 0x101b..0x1028
        code.push(0xc3); // 0x1029: ret
        let bin = tiny_elf64(&code);
        let out = crate::cmd_search::xrefs(&bin, "0x1029", false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("call 1"), "call count: {text}");
        assert!(text.contains("jmp/jcc 1"), "jmp count: {text}");
        assert!(text.contains("call 0x1029"), "insn: {text}");
        assert!(text.contains("jmp 0x1029"), "insn: {text}");
    }

    #[test]
    fn xrefs_rip_relative_data() {
        // mov rax, [rip+0] at 0x1000 (7 bytes) -> rip_target = 0x1007
        let code = [0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let bin = tiny_elf64(&code);
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_offset(0x100, code.len());
        assert_eq!(d.insns[0].rip_target, Some(0x1007));
        // xrefs to 0x1007 must find it as a data reference
        let out = crate::cmd_search::xrefs(&bin, "0x1007", false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("data 1"), "data xref: {text}");
    }

    #[test]
    fn utf16_strings_extracted() {
        // "Hi" + "AB" in UTF-16LE inside a tiny ELF .text
        let mut code: Vec<u8> = vec![
            b'H', 0, b'i', 0, 0, 0, // Hi (len 2 chars)
            b'A', 0, b'B', 0, 0, 0, // AB (len 2 chars)
        ];
        let bin = tiny_elf64(&code);
        let out = crate::cmd_analyze::strings(&bin, 2, "", None, true, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("Hi"), "got: {text}");
        assert!(text.contains("AB"), "got: {text}");
        // min_len 4 chars filters both out
        let out = crate::cmd_analyze::strings(&bin, 4, "", None, true, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(!text.contains("Hi\n"), "got: {text}");
        code.clear();
    }

    #[test]
    fn strings_limit_truncates() {
        // the tiny_elf64 fixture also embeds ".text"/".shstrtab" strings, so
        // filter to the marker run only and check the limit logic
        let code: Vec<u8> = b"AAAABBBBCCCC".to_vec();
        let bin = tiny_elf64(&code);
        let out = crate::cmd_analyze::strings(&bin, 4, "AAAA", Some(2), false, true).unwrap();
        let v = match out {
            crate::out::Out::Json(v) => v,
            _ => panic!("expected json"),
        };
        assert_eq!(v["total"], 1, "one matching run: {v}");
        assert_eq!(v["shown"], 1);
        assert_eq!(v["strings"][0]["text"], "AAAABBBBCCCC");
    }

    #[test]
    fn disasm_until_ret_stops_at_ret() {
        // mov, nop, nop, ret, nop, ret: until-ret must cut after the FIRST ret
        let code = [0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3, 0x90, 0xc3];
        let bin = tiny_elf64(&code);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 100, None, true, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("ret"), "got: {text}");
        // count the instruction lines: 4 insns (mov, nop, nop, ret)
        let lines = text
            .lines()
            .filter(|l| l.contains("mov") || l.contains("nop") || l.contains("ret"))
            .count();
        assert_eq!(lines, 4, "got: {text}");
        // and the last decoded insn is the ret at 0x1005
        let last = text.lines().rfind(|l: &&str| l.contains("ret")).unwrap();
        assert!(last.contains("0x1005"), "got: {last}");
    }

    #[test]
    fn md5_sha1_vectors() {
        use crate::hashes::{md5, sha1};
        assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5(b"The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        assert_eq!(sha1(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn entropy_window_profile() {
        // 512 zero bytes then 512 pseudorandom-ish bytes: two windows, second higher
        let mut code = vec![0u8; 512];
        let mut x: u64 = 0x1234_5678_9abc_def0;
        for i in 512..1024 {
            // xorshift64
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            code.push((x & 0xff) as u8);
            let _ = i;
        }
        let bin = tiny_elf64(&code);
        let out = crate::cmd_analyze::entropy(&bin, "+0x100", 1024, Some(512), false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("windows"), "got: {text}");
        assert!(
            text.contains("0x500"),
            "second window at 0x100+0x400: {text}"
        );
        // zero window has entropy 0.0000, random one is high
        assert!(text.contains("0.0000"), "zero window: {text}");
        // json variant
        let out = crate::cmd_analyze::entropy(&bin, "+0x100", 1024, Some(512), true).unwrap();
        let v = match out {
            crate::out::Out::Json(v) => v,
            _ => panic!("expected json"),
        };
        assert_eq!(v["windows"], 2);
        assert!(v["peak_entropy"].as_str().unwrap().parse::<f64>().unwrap() > 7.0);
    }

    #[test]
    fn symbols_limit_truncates() {
        let bin = match test_elf() {
            Some(b) => b,
            None => return,
        };
        let out = crate::cmd_analyze::symbols(&bin, "", None, Some(5), true).unwrap();
        let v = match out {
            crate::out::Out::Json(v) => v,
            _ => panic!("expected json"),
        };
        assert_eq!(v["shown"], 5);
        assert!(v["total"].as_u64().unwrap() > 5);
    }

    #[test]
    fn carve_new_magics() {
        // RAR / 7z / CAB / xz / zstd / OLE2 / UPX signatures are recognized in
        // a non-ELF/PE container — carve reads the file directly, but the
        // command API needs a path; exercise via a temp file
        let dir = std::env::temp_dir().join("ba_test_carve");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("sig.bin");
        let data = b"xxRar!\x1a\x07\x00yy7z\xbc\xaf\x27\x1czzMSCFww\xfd7zXZ\x00vv\x28\xb5\x2f\xfduu\xd0\xcf\x11\xe0ttUPX!";
        std::fs::write(&p, data).unwrap();
        let out = crate::cmd_mod::carve(p.to_str().unwrap(), true, 0).unwrap();
        let v = match out {
            crate::out::Out::Json(v) => v,
            _ => panic!("expected json"),
        };
        let kinds: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|h| h["kind"].as_str())
            .collect();
        for k in ["RAR", "7z", "CAB", "xz", "zstd", "OLE2", "UPX"] {
            assert!(kinds.contains(&k), "missing {k} in {kinds:?}");
        }
        let _ = std::fs::remove_file(&p);
    }

    // ===== 0.2.1 audit regression tests =====

    fn tiny_elf(payload: &[u8]) -> crate::core::Binary {
        // build a minimal ELF64 with .text == payload
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        buf[58..60].copy_from_slice(&64u16.to_le_bytes());
        let data_off = 0x100usize;
        buf.extend(std::iter::repeat_n(0, data_off - 64));
        buf.extend_from_slice(payload);
        let shstr_off = buf.len();
        buf.extend_from_slice(b"\0.text\0.shstrtab\0");
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;
        buf[40..48].copy_from_slice(&shoff.to_le_bytes());
        buf[60..62].copy_from_slice(&3u16.to_le_bytes());
        buf[62..64].copy_from_slice(&2u16.to_le_bytes());
        fn hdr32(fields: &[u32]) -> Vec<u8> {
            fields.iter().flat_map(|f| f.to_le_bytes()).collect()
        }
        let sh_text = {
            let mut v = hdr32(&[1, 1, 6, 0]);
            v.extend_from_slice(&0x1000u64.to_le_bytes());
            v.extend_from_slice(&(data_off as u64).to_le_bytes());
            v.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            v.extend_from_slice(&hdr32(&[0, 0, 1, 0]));
            v.extend_from_slice(&0u64.to_le_bytes());
            v
        };
        let sh_shstr = {
            let mut v = hdr32(&[7, 3, 0, 0]);
            v.extend_from_slice(&0u64.to_le_bytes());
            v.extend_from_slice(&(shstr_off as u64).to_le_bytes());
            v.extend_from_slice(&16u64.to_le_bytes());
            v.extend_from_slice(&hdr32(&[0, 0, 1, 0]));
            v.extend_from_slice(&0u64.to_le_bytes());
            v
        };
        buf.extend(std::iter::repeat_n(0, 64));
        buf.extend_from_slice(&sh_text);
        buf.extend_from_slice(&sh_shstr);
        crate::core::Binary::from_data(buf, "test.elf").expect("parse")
    }

    /// Minimal ELF **i386** (class 1, machine 3) with .text == payload:
    /// decoder context for the 32-bit-only opcodes (arpl/lds/salc/moffs32).
    fn tiny_elf32(payload: &[u8]) -> crate::core::Binary {
        let shstr: &[u8] = b"\0.text\0.shstrtab\0";
        let data_off = 0x100usize;
        // header (52) + pad to data_off + payload + shstrtab, then 3 shdrs
        let shoff = ((data_off + payload.len() + shstr.len()) + 3) & !3usize;
        let mut buf = vec![0u8; shoff + 3 * 40];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 1; // 32-bit
        buf[5] = 1; // LE
        buf[6] = 1; // version
        buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // EXEC
        buf[18..20].copy_from_slice(&3u16.to_le_bytes()); // i386
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
        buf[24..28].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        buf[28..32].copy_from_slice(&0u32.to_le_bytes()); // e_phoff
        buf[32..36].copy_from_slice(&(shoff as u32).to_le_bytes()); // e_shoff
        buf[36..40].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        buf[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
        buf[42..44].copy_from_slice(&0u16.to_le_bytes()); // e_phentsize
        buf[44..46].copy_from_slice(&0u16.to_le_bytes()); // e_phnum
        buf[46] = 40; // e_shentsize (byte @46)
        buf[48..50].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        buf[50..52].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx
        buf[data_off..data_off + payload.len()].copy_from_slice(payload);
        let shstr_off = data_off + payload.len();
        buf[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
        // section headers: [0]=null, [1]=.text, [2]=.shstrtab
        let mut sh = |idx: usize, name: u32, typ: u32, addr: u32, off: u32, size: u32| {
            let base = shoff + idx * 40;
            let fields = [name, 0, typ, addr, off, off, size, 0, 4, 1]; // 10*4 = 40
            for (i, f) in fields.iter().enumerate() {
                buf[base + i * 4..base + i * 4 + 4].copy_from_slice(&f.to_le_bytes());
            }
        };
        sh(0, 0, 0, 0, 0, 0);
        sh(1, 1, 1, 0x1000, data_off as u32, payload.len() as u32); // .text
        sh(2, 7, 3, 0, shstr_off as u32, shstr.len() as u32); // .shstrtab
        crate::core::Binary::from_data(buf, "test32.elf").expect("parse i386")
    }

    #[test]
    fn disasm_resync_on_data_island() {
        // "blk transfo" contains 0x62 ('b') which decodes as an EVEX prefix
        // with a garbage map; the sweep must emit db bytes and continue
        let payload: Vec<u8> = [0x48, 0x89, 0xc3]
            .iter()
            .chain(b"blk transfo".iter())
            .chain([0x48, 0x31, 0xc0, 0xc3].iter())
            .copied()
            .collect();
        let bin = tiny_elf(&payload);
        let dec = crate::disasm::Decoder::new(&bin);
        let d = dec.disasm_at_offset(0x100, 64);
        assert!(
            d.insns.len() > 5,
            "resync must continue past the island, got {} insns, stopped {:?}",
            d.insns.len(),
            d.stopped
        );
        // the trailing ret (0xc3) must be decoded — the island did not
        // stop the sweep before it
        assert!(
            d.insns.iter().any(|i| i.kind == "ret"),
            "ret after the island must be decoded"
        );
    }

    #[test]
    fn hashes_match_reference_on_boundaries() {
        // every length class of the Merkle-Damgard padding (incl. the
        // two-block tail at n % 64 in 56..=63)
        for n in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 3000] {
            let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
            // MD5 vs a known-good independent implementation vector:
            // verified against md5sum/sha1sum/sha256sum in e2e; here we
            // check determinism + length classes don't panic and produce
            // stable digests
            let m1 = crate::hashes::md5(&data);
            let m2 = crate::hashes::md5(&data);
            assert_eq!(m1, m2, "md5 nondeterministic at n={n}");
            assert_eq!(m1.len(), 32);
            let s1 = crate::hashes::sha1(&data);
            assert_eq!(s1.len(), 40);
            let q1 = crate::sha256::sha256(&data);
            assert_eq!(q1.len(), 64);
        }
        // known vectors
        assert_eq!(
            crate::hashes::md5(b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            crate::hashes::sha1(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            crate::sha256::sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // n=56 and n=64 exercise the extra-block padding path
        assert_eq!(
            crate::sha256::sha256(&[0x61; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    #[test]
    fn utf16_cyrillic_extracted() {
        let cyr: Vec<u8> = "\u{041f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain(std::iter::repeat_n(0u8, 2))
            .collect();
        let bin = tiny_elf(&cyr);
        let out = crate::cmd_analyze::strings(&bin, 2, "", None, true, true).unwrap();
        let v = match out {
            crate::out::Out::Json(v) => v,
            _ => panic!("expected json"),
        };
        // without --limit the JSON payload is a flat array of string entries
        let arr = v.as_array().unwrap();
        assert!(!arr.is_empty(), "at least one utf16 string expected");
        let texts: Vec<&str> = arr.iter().filter_map(|s| s["text"].as_str()).collect();
        assert!(
            texts
                .iter()
                .any(|t| t.contains("\u{041f}\u{0440}\u{0438}\u{0432}")),
            "cyrillic string must be extracted, got {texts:?}"
        );
    }

    #[test]
    fn mdpad_block_stream_is_exact() {
        // property test embedded in mdpad.rs covers all lengths; here check
        // a couple of multi-block inputs produce the classic padded layout
        let data = vec![0x61u8; 200]; // 3 full blocks + 8 tail bytes
        let mut blocks = 0;
        crate::mdpad::for_each_block(&data, false, |_| blocks += 1);
        assert_eq!(blocks, 4, "200 bytes + padding must be 4 blocks");
        // a tail of exactly 56..63 bytes needs the extra zero block
        for (n, want) in [(119usize, 2usize), (120, 3), (127, 3)] {
            let data = vec![0x61u8; n];
            let mut blocks = 0;
            crate::mdpad::for_each_block(&data, false, |_| blocks += 1);
            assert_eq!(blocks, want, "n={n} must pad into {want} blocks");
        }
    }

    // ---------- decoder regression tests (defects found by disasm_metric
    // ---------- on AutoChart 0.2.3: 44 real length mismatches -> 0) ----------

    #[test]
    fn decoder_i386_rare_opcodes_lengths() {
        // i386: opcodes that fell through to `db` (len 1) before the fix.
        // e6 43 out 0x43,al | e5 43 in eax,0x43 | e7 43 out 0x43,eax
        // ca 12 34 retf 0x3412 | cb retf | d6 salc | 63 d1 arpl
        // c5 40 00 lds eax,[eax] (32-bit C5 = LES/LDS, not VEX)
        let cases: &[(&[u8], usize, &str)] = &[
            (&[0xe6, 0x43], 2, "out"),
            (&[0xe5, 0x43], 2, "in"),
            (&[0xe7, 0x43], 2, "out"),
            (&[0xca, 0x12, 0x34], 3, "retf"),
            (&[0xcb], 1, "retf"),
            (&[0xd6], 1, "salc"),
            (&[0x63, 0xd1], 2, "arpl"),
            (&[0xc5, 0x40, 0x00], 3, "lds/les"),
        ];
        for (code, want_len, want_mn) in cases {
            let bin = tiny_elf32(code);
            let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, false).unwrap();
            let text = match out {
                crate::out::Out::Text(t) => t,
                _ => panic!("expected text"),
            };
            assert!(
                text.contains(want_mn),
                "bytes {code:x?}: mnemonic {want_mn} missing in: {text}"
            );
            let bin2 = tiny_elf32(code);
            let outj = crate::cmd_analyze::disasm(&bin2, "0x1000", 1, None, false, true).unwrap();
            let j = match outj {
                crate::out::Out::RawJson(s) => {
                    serde_json::from_str::<serde_json::Value>(&s).expect("parse raw json")
                }
                _ => panic!("expected raw json"),
            };
            let insns = j["insns"].as_array().unwrap();
            assert_eq!(
                insns[0]["len"].as_u64().unwrap() as usize,
                *want_len,
                "bytes {code:x?}: len {} want {want_len}",
                insns[0]["len"]
            );
        }
    }

    #[test]
    fn decoder_moffs_66_in_i386() {
        // `66 a3 92 a6 7d 00` in a 32-bit binary: mov ds:0x7da692, ax —
        // the 66 prefix narrows the REGISTER (ax) but the moffs ADDRESS
        // stays 32-bit: total 6 bytes (objdump-compatible).
        let code = [0x66u8, 0xa3, 0x92, 0xa6, 0x7d, 0x00];
        let bin = tiny_elf32(&code);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => {
                serde_json::from_str::<serde_json::Value>(&s).expect("parse raw json")
            }
            _ => panic!("expected raw json"),
        };
        let insn = &j["insns"][0];
        assert_eq!(insn["len"].as_u64().unwrap(), 6, "got: {insn}");
        assert!(
            insn["operands"].as_str().unwrap().contains("ax"),
            "got: {insn}"
        );
    }

    #[test]
    fn decoder_fwait_fstsw_ax() {
        // `9b 9b df e0` — objdump renders the double FWAIT glue as one
        // `fstsw ax` instruction (4 bytes), not fnstsw.
        let code = [0x9bu8, 0x9b, 0xdf, 0xe0];
        let bin = tiny_elf32(&code);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, false).unwrap();
        let text = match out {
            crate::out::Out::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert!(text.contains("fstsw"), "got: {text}");
    }

    // ---- R4 regression tests (opcode coverage edition 3) ----

    fn one_json(bin: &crate::core::Binary, is64_json: bool) -> serde_json::Value {
        let out = crate::cmd_analyze::disasm(bin, "0x1000", 2, None, false, true).unwrap();
        match out {
            crate::out::Out::RawJson(s) => serde_json::from_str(&s).unwrap(),
            _ => panic!("expected raw json (is64={is64_json})"),
        }
    }

    #[test]
    fn decoder_enter_imm3_no_panic() {
        // 0xc8 (ENTER imm16,imm8): imm=3 must not fall into the u64 read arm
        // (former slice-overflow panic, defect #45).
        let code = [0xc8u8, 0x9f, 0x00, 0x00, 0x90];
        let bin = tiny_elf32(&code);
        let j = one_json(&bin, false);
        assert_eq!(j["insns"][0]["len"].as_u64().unwrap(), 4, "got: {j}");
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "enter");
    }

    #[test]
    fn decoder_callf_jmpf_imm6_no_panic() {
        // 0x9a/0xea far pointers (imm=6): no slice overflow (defect #46),
        // selector:offset rendering, len 7.
        let code = [0x9au8, 0x34, 0x12, 0x00, 0x00, 0x23, 0x00, 0x90];
        let bin = tiny_elf32(&code);
        let j = one_json(&bin, false);
        assert_eq!(j["insns"][0]["len"].as_u64().unwrap(), 7, "got: {j}");
        assert!(
            j["insns"][0]["operands"]
                .as_str()
                .unwrap()
                .contains("0x23:0x1234"),
            "got: {j}"
        );
    }

    #[test]
    fn decoder_x87_reg_forms() {
        // Register-form x87 (mod=3): FCMOV rows (DA/DB), FFREE/FUCOM (DD),
        // swapped FSUB/FSUBR + FDIV/FDIVR (DC), FCOMPP only at DE D9,
        // FFREEP (DF C0+i), FUCOMI/FCOMI (DB/DF), FUCOMPP only at DA E9.
        let cases: &[(u8, u8, &str)] = &[
            (0xda, 0xc1, "fcmovb"),  // was: fiadd (defect #47)
            (0xdb, 0xc1, "fcmovnb"), // was: fild (defect #48)
            (0xdd, 0xc1, "ffree"),   // was: fld (defect #49)
            (0xdc, 0xe1, "fsubr"),   // SDM: DC E0+i = FSUBR (defect #50)
            (0xde, 0xe1, "fsubrp"),  // DE E0+i = FSUBRP (SDM swap)
            (0xde, 0xe9, "fsubp"),   // DE E8+i = FSUBP
            (0xde, 0xd9, "fcompp"),  // only DE D9
            (0xda, 0xe9, "fucompp"), // only DA E9
            (0xdf, 0xc1, "ffreep"),  // was: fild
            (0xdf, 0xe9, "fucompi"), // was missing
            (0xdb, 0xe9, "fucomi"),
        ];
        for &(row, mr, want) in cases {
            let code = [row, mr, 0x90];
            let bin = tiny_elf32(&code);
            let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
            let j = match out {
                crate::out::Out::RawJson(s) => {
                    serde_json::from_str::<serde_json::Value>(&s).unwrap()
                }
                _ => panic!("expected raw json"),
            };
            assert_eq!(
                j["insns"][0]["mnemonic"].as_str().unwrap(),
                want,
                "bytes {row:02x} {mr:02x}: got {j}"
            );
        }
    }

    #[test]
    fn decoder_string_ops_rep_glue_and_suffix() {
        // rep/repne glue + b/w/d/q suffixes (q only with REX.W, defect #53)
        let cases: &[(Vec<u8>, &str, bool)] = &[
            (vec![0xf3, 0xa4], "rep movsb", false),
            (vec![0xf2, 0xae], "repne scasb", false),
            (vec![0xa5], "movsd", false), // 32-bit: movsd
            (vec![0x66, 0xa5], "movsw", false),
            (vec![0xab], "stosd", false),
        ];
        for (code, want, _) in cases {
            let bin = tiny_elf32(code);
            let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
            let j = match out {
                crate::out::Out::RawJson(s) => {
                    serde_json::from_str::<serde_json::Value>(&s).unwrap()
                }
                _ => panic!("expected raw json"),
            };
            assert_eq!(
                j["insns"][0]["mnemonic"].as_str().unwrap(),
                *want,
                "bytes {code:02x?}: got {j}"
            );
        }
        // x64: A5 without REX.W is movsd (NOT movsq); with REX.W movsq
        let bin = tiny_elf64(&[0xa5, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(
            j["insns"][0]["mnemonic"].as_str().unwrap(),
            "movsd",
            "got {j}"
        );
        let bin = tiny_elf64(&[0x48, 0xa5, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(
            j["insns"][0]["mnemonic"].as_str().unwrap(),
            "movsq",
            "got {j}"
        );
    }

    #[test]
    fn decoder_mode_aware_one_byte_names() {
        // pushfd/popfd (i386) vs pushfq/popfq (x64); cwde default, cdqe with
        // REX.W; loopne/loope/jecxz; concrete flag ops.
        let bin = tiny_elf32(&[0x9c, 0x9d, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 2, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "pushfd");
        assert_eq!(j["insns"][1]["mnemonic"].as_str().unwrap(), "popfd");

        let bin = tiny_elf64(&[0x9c, 0x9d, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 2, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "pushfq");
        assert_eq!(j["insns"][1]["mnemonic"].as_str().unwrap(), "popfq");

        let bin = tiny_elf64(&[0x98, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(
            j["insns"][0]["mnemonic"].as_str().unwrap(),
            "cwde",
            "got {j}"
        );

        let bin = tiny_elf32(&[0xe0, 0x10, 0xe1, 0x10, 0xe3, 0x10, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 3, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "loopne");
        assert_eq!(j["insns"][1]["mnemonic"].as_str().unwrap(), "loope");
        assert_eq!(j["insns"][2]["mnemonic"].as_str().unwrap(), "jecxz");
    }

    #[test]
    fn decoder_movabs_and_pinsrw() {
        // REX.W mov r64, imm64 renders as movabs (capstone/objdump convention)
        let bin = tiny_elf64(&[0x48, 0xb8, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(
            j["insns"][0]["mnemonic"].as_str().unwrap(),
            "movabs",
            "got {j}"
        );
        assert_eq!(j["insns"][0]["len"].as_u64().unwrap(), 10);

        // 0F C4 = pinsrw (concrete, not a sketch)
        let bin = tiny_elf64(&[0x0f, 0xc4, 0xc0, 0x7f, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "pinsrw");
    }

    #[test]
    fn decoder_three_byte_maps_named() {
        // 0F 38 00 = pshufb (SSSE3), 0F 3A 0F = palignr: named, not placeholders
        let bin = tiny_elf32(&[0x0f, 0x38, 0x00, 0xc0, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(
            j["insns"][0]["mnemonic"].as_str().unwrap(),
            "pshufb",
            "got {j}"
        );
        assert_eq!(j["insns"][0]["len"].as_u64().unwrap(), 4);

        let bin = tiny_elf32(&[0x0f, 0x3a, 0x0f, 0xc0, 0x7f, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "palignr");
        assert_eq!(j["insns"][0]["len"].as_u64().unwrap(), 5);
    }

    #[test]
    fn decoder_vex_shift_digit_names() {
        // VEX.128.66.0F 73 /6 ib = vpsllq (by reg digit, not a sketch)
        let bin = tiny_elf64(&[0xc4, 0xe1, 0xf9, 0x73, 0xf1, 0x7f, 0x90]);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 1, None, false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(
            j["insns"][0]["mnemonic"].as_str().unwrap(),
            "vpsllq",
            "got {j}"
        );
    }

    // ---- R5 confidence levels ----

    #[test]
    fn confidence_levels_in_json() {
        // concrete table name -> high; placeholder/fallback -> low
        let code = [0x48u8, 0x89, 0xc5, 0x90]; // mov rbp, rax; nop
        let bin = tiny_elf64(&code);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 2, Some(4), false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["confidence"].as_str().unwrap(), "high");
        assert_eq!(j["insns"][1]["confidence"].as_str().unwrap(), "high");
        let sum = &j["confidence_summary"];
        assert_eq!(sum["high"].as_u64().unwrap(), 2);
        assert_eq!(sum["low"].as_u64().unwrap(), 0);

        // placeholder three-byte opcode and x87 fallback -> low
        let code = [0x0fu8, 0x38, 0xab, 0xc0, 0xd9, 0xd9];
        let bin = tiny_elf32(&code);
        let out = crate::cmd_analyze::disasm(&bin, "0x1000", 2, Some(6), false, true).unwrap();
        let j = match out {
            crate::out::Out::RawJson(s) => serde_json::from_str::<serde_json::Value>(&s).unwrap(),
            _ => panic!("expected raw json"),
        };
        assert_eq!(j["insns"][0]["confidence"].as_str().unwrap(), "low");
        assert_eq!(j["insns"][0]["mnemonic"].as_str().unwrap(), "op_0f_38_ab");
        assert_eq!(j["insns"][1]["confidence"].as_str().unwrap(), "low");
        assert_eq!(j["confidence_summary"]["low"].as_u64().unwrap(), 2);
    }
}
