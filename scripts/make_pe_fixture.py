#!/usr/bin/env python3
"""Generate minimal valid PE64 files for e2e tests (no mingw needed):
/tmp/t.exe       — console EXE (main returns 3)
/tmp/pe_dll.dll — DLL with an export directory (AddOne, Another)
"""
import struct
import sys


def make_pe(is_dll: bool, exe_path: str, dll_path: str) -> None:
    # single .text section: RVA 0x1000, file offset 0x400
    if is_dll:
        code = bytes([
            0x48, 0x89, 0xc8,        # mov rax, rcx
            0x48, 0x83, 0xc0, 0x01,  # add rax, 1
            0xc3,                    # ret
        ]) + b"\xcc" * 7
    else:
        code = bytes([0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3]) + b"\xcc" * 8

    machine = 0x8664
    nsec = 1
    opt_size = 240
    chars = 0x2000 if is_dll else 0x0002  # IMAGE_FILE_DLL | EXECUTABLE

    exp_rva = 0x1100 if is_dll else 0
    exp_sz = 75 if is_dll else 0   # dir(40) + funcs(8) + ptrs(8) + names(19)

    # DOS header: 64 bytes, e_lfanew at 0x3c -> 0x40, PE\0\0 right there
    dos = b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack(
        "<HHIIIHH",
        machine, nsec, 0, 0x40 + 24 + opt_size, 0, opt_size, chars,
    )
    subsys = 3 if is_dll else 2
    # PE32+ optional header (no BaseOfData; ImageBase is 8 bytes).
    # Fixed part is 112 bytes, then 16 data directories of 8 bytes each.
    opt = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 0, 0,                 # magic, linker ver
        len(code), 0, 0,             # size of code / init / uninit
        0x1000,                      # entry point RVA
        0x1000,                      # base of code
        0x100000,                    # image base
        0x1000, 0x200,               # section/file alignment
        6, 0,                        # OS version
        0, 0,                        # image version
        6, 0,                        # subsystem version
        0,                           # win32 ver
        0x2000,                      # size of image
        0x400,                       # size of headers
        0,                           # checksum
        subsys, 0,                   # subsystem, dll characteristics
        0x100000, 0x1000,            # stack reserve/commit
        0x100000, 0x1000,            # heap reserve/commit
        0,                           # loader flags
        16,                          # number of RVA entries
    )
    opt += b"\x00" * (16 * 8)        # 16 empty data directories
    if is_dll:
        # data dir 0 = export table
        off = 112
        opt = opt[:off] + struct.pack("<II", exp_rva, exp_sz) + opt[off + 8 :]

    sec = struct.pack(
        # name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, ...
        "<8sIIIIHHI",
        b".text", 0x600, 0x1000, 0x600, 0x400, 0, 0, 0x60000020,
    )
    head = dos + pe_sig + coff + opt + sec
    head += b"\x00" * (0x400 - len(head))
    # .text raw data at file 0x400..0x800 (RVA 0x1000..0x1400)
    body = bytearray(b"\x00" * 0x600)
    body[0:len(code)] = code
    if is_dll:
        # export blob lives INSIDE .text raw data at RVA 0x1100 (file 0x500)
        funcs = struct.pack("<II", 0x1010, 0x1010)   # two function RVAs
        names = b"AddOne\x00Another\x00"
        ords = struct.pack("<HH", 0, 1)              # ordinal indices
        dir_off = 0x1100 - 0x1000                    # 0x100 inside body
        funcs_off = dir_off + 40
        ptrs_off = funcs_off + len(funcs)
        ords_off = ptrs_off + 8                      # two name pointers
        names_off = ords_off + len(ords)
        rva_base = 0x1000
        struct.pack_into(
            # chars, ts, majVer, minVer, Name, Base, NFuncs, NNames,
            # AddrFuncs, AddrNames, AddrOrds
            "<IIHHIIIIIII", body, dir_off,
            0, 0, 0, 0,
            rva_base + names_off, 1,
            2, 2,
            rva_base + funcs_off, rva_base + ptrs_off, rva_base + ords_off,
        )
        body[funcs_off:funcs_off + len(funcs)] = funcs
        struct.pack_into("<I", body, ptrs_off, rva_base + names_off)
        struct.pack_into("<I", body, ptrs_off + 4, rva_base + names_off + 7)
        body[ords_off:ords_off + len(ords)] = ords
        body[names_off:names_off + len(names)] = names
    out = head + bytes(body)

    path = dll_path if is_dll else exe_path
    with open(path, "wb") as f:
        f.write(out)
    print(f"{path}: {len(out)} bytes, dll={is_dll}")


if __name__ == "__main__":
    exe = sys.argv[1] if len(sys.argv) > 1 else "/tmp/t.exe"
    dll = sys.argv[2] if len(sys.argv) > 2 else "/tmp/pe_dll.dll"
    make_pe(False, exe, dll)
    make_pe(True, exe, dll)
