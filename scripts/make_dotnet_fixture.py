#!/usr/bin/env python3
"""Minimal .NET (CIL) PE32 console exe: COM descriptor dir 14 points to a
72-byte IMAGE_COR20_HEADER with a tiny metadata root. No real IL semantics —
the parser only needs the header layout."""
import struct, sys

def build(path):
    # IMAGE_COR20_HEADER (72 bytes)
    # ECMA-335 II.25.3.2 (72 bytes): cb, ver, MetaData(8), Flags, Entry,
    # Resources(8), StrongName(8), CodeManagerTable(4), VTableFixups(8),
    # ExportAddressTableJumps(8), ManagedNativeHeader(8)
    # winnt.h IMAGE_COR20_HEADER: CodeManagerTable is a full DIRECTORY (8)
    cor = struct.pack('<IHH' + 'II' + 'II' + 'II' + 'II' + 'II' + 'II' + 'II' + 'II',
        72,           # cb
        2, 5,         # Major/MinorRuntimeVersion -> v2.0.50727
        0x2080, 0x30, # MetaData RVA/Size
        0x1,          # Flags: ILONLY
        0x06000001,   # EntryPointToken (MethodDef token)
        0, 0,         # Resources RVA/Size
        0, 0,         # StrongNameSignature RVA/Size
        0, 0,         # CodeManagerTable RVA/Size
        0, 0,         # VTableFixups RVA/Size
        0, 0,         # ExportAddressTableJumps RVA/Size
        0, 0,         # ManagedNativeHeader RVA/Size
    )
    assert len(cor) == 72, len(cor)
    code = b'\x2a'  # ret (IL)
    meta = b'BSJB' + b'\x00' * 0x2c  # metadata magic + padding
    # .text layout: cor header at 0x200 (rva 0x2000), code 0x260, meta 0x280
    text = bytearray(0x400)
    text[0x00:0x48] = cor
    text[0x60:0x61] = code
    text[0x80:0x80+len(meta)] = meta

    dos = b'MZ' + b'\x00'*0x3a + struct.pack('<I', 0x40)
    machine, nsec, opt_size, chars = 0x14c, 1, 224, 0x0102
    coff = struct.pack('<HHIIIHH', machine, nsec, 0, 0, 0, opt_size, chars)
    # PE32 optional header, mirroring the proven make_pe_fixture layout
    # (fixed part 96 bytes + 16 data directories of 8 bytes = 224)
    opt = struct.pack(
        '<HBBIIIIIII' + 'II' + 'HHHHHH' + 'IIIIHH' + 'IIII' + 'II',
        0x10b,        # magic PE32
        0, 0,         # linker ver
        16, 16, 0,    # size of code / init / uninit
        0x2000,       # entry point RVA
        0x2000,       # base of code
        0x2000,       # base of data
        0x400000,     # image base (PE32: 4-byte)
        0x2000, 0x200, # section / file alignment
        4, 0,         # OS version
        0, 0,         # image version
        4, 0,         # subsystem version
        0,            # win32 version
        0x3000,       # size of image
        0x400,        # size of headers
        0,            # checksum
        3,            # subsystem CUI
        0x8100,       # dll characteristics (DYNAMIC_BASE|NX_COMPAT)
        0x100000, 0x1000,  # stack reserve/commit
        0x100000, 0x1000,  # heap reserve/commit
        0,            # loader flags
        16,           # number of RVA entries
    )
    assert len(opt) == 96, len(opt)
    dd = bytearray(16*8)
    # dir 14 = COM descriptor: RVA 0x2000, size 72
    struct.pack_into('<II', dd, 14*8, 0x2000, 72)
    opt += bytes(dd)
    # section header: name, VirtualSize, VirtualAddress, SizeOfRawData,
    # PointerToRawData, PointerToRelocs(0), PointerToLines(0), NumRelocs(0),
    # NumLines(0), Characteristics
    sec = struct.pack('<8sIIIIIIHHI',
                      b'.text\x00\x00\x00',
                      0x48 + 0x30,  # virtual size
                      0x2000,       # virtual address (RVA)
                      0x400,        # size of raw data
                      0x400,        # pointer to raw data
                      0, 0, 0, 0,
                      0x60000020)   # code | execute | read
    img = dos + b'PE\x00\x00' + coff + opt + sec + bytes(text)
    # .text raw data lands at file 0x400; pad the header gap explicitly
    gap = 0x400 - (len(dos) + 4 + len(coff) + len(opt) + len(sec))
    assert gap >= 0, gap
    img = dos + b'PE\x00\x00' + coff + opt + sec + b'\x00' * gap + bytes(text)
    open(path, 'wb').write(img)
    print(f"{path}: {len(img)} bytes")

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '/tmp/dotnet.exe')
