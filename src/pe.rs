//! Minimal pure-Rust PE parser (32/64) focused on what an analysis agent
//! needs: headers, sections, exports, imports.

use crate::core::{shannon_entropy, Export, Import, Section};
use anyhow::{bail, Result};

#[allow(dead_code)]
pub struct Pe {
    pub is64: bool,
    pub machine: u16,
    pub timestamp: u32,
    pub entry: u64, // VA (image base + RVA)
    pub image_base: u64,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub runtime_versions: Vec<(String, String)>,
    /// VS_VERSIONINFO key/value pairs (CompanyName, FileVersion, ...) from
    /// the RT_VERSION resource, when present.
    pub version_info: Vec<(String, String)>,
    /// .NET (CLR) header summary when the COM descriptor directory is present.
    pub dotnet: Option<DotNetInfo>,
}

/// Summary of the IMAGE_COR20_HEADER (.NET metadata root).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DotNetInfo {
    /// CLR runtime version string inferred from the major/minor numbers
    pub runtime_version: String,
    pub flags: String,
    /// RVA of the embedded metadata blob
    pub metadata_rva: u64,
    pub metadata_size: u64,
    /// entry point token (or RVA when the native-entrypoint flag is set)
    pub entry_point_token: String,
}

impl Pe {
    pub fn parse(data: &[u8]) -> Result<Pe> {
        if data.len() < 0x40 {
            bail!("PE too small");
        }
        if data[0] != b'M' || data[1] != b'Z' {
            bail!("no MZ signature");
        }
        let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
        if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
            bail!("no PE signature");
        }

        let machine = u16::from_le_bytes(data[pe_off + 4..pe_off + 6].try_into().unwrap());
        let nsections = u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap());
        let timestamp = u32::from_le_bytes(data[pe_off + 8..pe_off + 12].try_into().unwrap());
        let characteristics =
            u16::from_le_bytes(data[pe_off + 22..pe_off + 24].try_into().unwrap());
        let opt_size =
            u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;

        let opt = pe_off + 24;
        if opt + opt_size > data.len() || opt_size < 64 {
            bail!("bad optional header");
        }
        let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap());
        let is64 = magic == 0x20b;
        if !is64 && magic != 0x10b {
            bail!("unsupported optional header magic {magic:#x}");
        }

        let entry_rva = u32::from_le_bytes(data[opt + 16..opt + 20].try_into().unwrap()) as u64;
        let image_base = if is64 {
            u64::from_le_bytes(data[opt + 24..opt + 32].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[opt + 28..opt + 32].try_into().unwrap()) as u64
        };
        let subsystem = u16::from_le_bytes(data[opt + 68..opt + 70].try_into().unwrap());
        let dll_characteristics = u16::from_le_bytes(data[opt + 70..opt + 72].try_into().unwrap());
        let size_of_headers = u32::from_le_bytes(data[opt + 60..opt + 64].try_into().unwrap());

        let section_table = opt + opt_size;
        let mut sections = Vec::new();
        for i in 0..nsections as usize {
            let h = section_table + i * 40;
            if h + 40 > data.len() {
                break;
            }
            let name: String = data[h..h + 8]
                .split(|&c| c == 0)
                .next()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .unwrap_or_default();
            let vsize = u32::from_le_bytes(data[h + 8..h + 12].try_into().unwrap()) as u64;
            let vaddr = u32::from_le_bytes(data[h + 12..h + 16].try_into().unwrap()) as u64;
            let raw_size = u32::from_le_bytes(data[h + 16..h + 20].try_into().unwrap()) as u64;
            let raw_ptr = u32::from_le_bytes(data[h + 20..h + 24].try_into().unwrap()) as u64;
            let chars = u32::from_le_bytes(data[h + 36..h + 40].try_into().unwrap());
            let entropy = if raw_size > 0
                && (raw_ptr as usize).saturating_add(raw_size as usize) <= data.len()
            {
                Some(shannon_entropy(
                    &data[raw_ptr as usize..(raw_ptr as usize + raw_size as usize)],
                ))
            } else {
                None
            };
            sections.push(Section {
                kind: pe_section_kind(&name, chars),
                name,
                offset: raw_ptr,
                size: raw_size,
                memsz: vsize,
                vaddr,
                flags: pe_section_flags(chars),
                entropy,
            });
        }

        // data directories
        let num_dirs_off = if is64 { opt + 108 } else { opt + 92 };
        let num_dirs = u32::from_le_bytes(data[num_dirs_off..num_dirs_off + 4].try_into().unwrap());
        let dirs_off = num_dirs_off + 4;
        let dir = |idx: usize| -> Option<(u32, u32)> {
            if idx >= num_dirs as usize {
                return None;
            }
            let o = dirs_off + idx * 8;
            if o + 8 > data.len() {
                return None;
            }
            let rva = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
            let size = u32::from_le_bytes(data[o + 4..o + 8].try_into().unwrap());
            if rva == 0 {
                None
            } else {
                Some((rva, size))
            }
        };

        let rva_to_off = |rva: u32| -> Option<usize> {
            rva_to_offset_rva(rva, &sections, size_of_headers as u64)
        };

        // ---- exports ----
        let mut exports = Vec::new();
        if let Some((rva, _sz)) = dir(0) {
            if let Some(e) = rva_to_off(rva) {
                if e + 40 <= data.len() {
                    let ord_base = u32::from_le_bytes(data[e + 16..e + 20].try_into().unwrap());
                    let _ = ord_base;
                    let n_names =
                        u32::from_le_bytes(data[e + 24..e + 28].try_into().unwrap()) as usize;
                    let names_rva = u32::from_le_bytes(data[e + 32..e + 36].try_into().unwrap());
                    let funcs_rva = u32::from_le_bytes(data[e + 28..e + 32].try_into().unwrap());
                    let ords_rva = u32::from_le_bytes(data[e + 36..e + 40].try_into().unwrap());
                    if let Some(names_off) = rva_to_off(names_rva) {
                        for i in 0..n_names {
                            let no = names_off + i * 4;
                            if no + 4 > data.len() {
                                break;
                            }
                            let nrva = u32::from_le_bytes(data[no..no + 4].try_into().unwrap());
                            let name = rva_to_off(nrva)
                                .map(|o| read_cstr(data, o))
                                .unwrap_or_default();
                            // address via ordinal table
                            let mut addr = 0u64;
                            if let Some(oo) = rva_to_off(ords_rva) {
                                let o2 = oo + i * 2;
                                if o2 + 2 <= data.len() {
                                    let ordinal =
                                        u16::from_le_bytes(data[o2..o2 + 2].try_into().unwrap());
                                    if let Some(fo) = rva_to_off(funcs_rva) {
                                        let f = fo + ordinal as usize * 4;
                                        if f + 4 <= data.len() {
                                            addr = image_base
                                                + u32::from_le_bytes(
                                                    data[f..f + 4].try_into().unwrap(),
                                                )
                                                    as u64;
                                        }
                                    }
                                }
                            }
                            if !name.is_empty() {
                                exports.push(Export { name, addr });
                            }
                        }
                    }
                }
            }
        }

        // ---- imports ----
        let mut imports = Vec::new();
        if let Some((rva, _sz)) = dir(1) {
            if let Some(d) = rva_to_off(rva) {
                // array of IMAGE_IMPORT_DESCRIPTOR (20 bytes), terminated by all-zero
                let mut off = d;
                while off + 20 <= data.len() {
                    let original_first_thunk =
                        u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
                    let name_rva = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
                    let first_thunk =
                        u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
                    if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                        break;
                    }
                    let module = rva_to_off(name_rva)
                        .map(|o| read_cstr(data, o))
                        .unwrap_or_default();
                    // thunks: use OFT if present else FT
                    let thunk_rva = if original_first_thunk != 0 {
                        original_first_thunk
                    } else {
                        first_thunk
                    };
                    if let Some(mut t) = rva_to_off(thunk_rva) {
                        let entsz = if is64 { 8 } else { 4 };
                        let mut idx = 0;
                        while t + entsz <= data.len() {
                            let val = if is64 {
                                u64::from_le_bytes(data[t..t + 8].try_into().unwrap())
                            } else {
                                u32::from_le_bytes(data[t..t + 4].try_into().unwrap()) as u64
                            };
                            if val == 0 {
                                break;
                            }
                            // high bit set => import by ordinal
                            let by_ordinal = if is64 {
                                val & (1 << 63) != 0
                            } else {
                                val & (1 << 31) != 0
                            };
                            let name = if by_ordinal {
                                let ord = (val & 0xffff) as u32;
                                let known = well_known_ordinal(&module, ord);
                                match known {
                                    Some(n) => n.to_string(),
                                    None => format!("#{ord}"),
                                }
                            } else {
                                // IMAGE_IMPORT_BY_NAME: 2-byte hint then name, at RVA val
                                rva_to_off(val as u32)
                                    .map(|o| read_cstr(data, o + 2))
                                    .unwrap_or_default()
                            };
                            let addr = if is64 {
                                image_base + (first_thunk as u64 + idx * 8)
                            } else {
                                image_base + (first_thunk as u64 + idx * 4)
                            };
                            imports.push(Import {
                                module: module.clone(),
                                name,
                                addr,
                            });
                            t += entsz;
                            idx += 1;
                        }
                    }
                    off += 20;
                }
            }
        }

        let version_info = parse_version_info(data, pe_off, opt, is64, &sections, size_of_headers);
        let dotnet = parse_dotnet(data, opt, is64, &sections, size_of_headers);

        Ok(Pe {
            is64,
            machine,
            timestamp,
            entry: image_base + entry_rva,
            image_base,
            size_of_headers,
            subsystem,
            characteristics,
            dll_characteristics,
            sections,
            imports,
            exports,
            runtime_versions: Vec::new(),
            version_info,
            dotnet,
        })
    }

    /// RVA -> file offset
    pub fn rva_to_offset(&self, rva: u64) -> Result<u64> {
        rva_to_offset_rva(rva as u32, &self.sections, self.size_of_headers as u64)
            .map(|v| v as u64)
            .ok_or_else(|| anyhow::anyhow!("rva {rva:#x} not mapped to any section"))
    }
}

fn rva_to_offset_rva(rva: u32, sections: &[Section], size_of_headers: u64) -> Option<usize> {
    let rva = rva as u64;
    if rva < size_of_headers && size_of_headers != 0 {
        return Some(rva as usize);
    }
    for s in sections {
        let vsize = if s.memsz > 0 { s.memsz } else { s.size };
        if s.vaddr <= rva && rva < s.vaddr + vsize {
            let delta = rva - s.vaddr;
            if delta >= s.size {
                return None; // virtual-only
            }
            return Some((s.offset + delta) as usize);
        }
    }
    None
}

fn pe_section_kind(name: &str, chars: u32) -> String {
    if chars & 0x20000000 != 0 {
        "code".to_string()
    } else if chars & 0x80000000 != 0 && chars & 0x40000000 != 0 {
        "data".to_string()
    } else if chars & 0x80000000 != 0 {
        "rodata".to_string()
    } else if name == ".bss" {
        "bss".to_string()
    } else {
        "other".to_string()
    }
}

fn pe_section_flags(chars: u32) -> String {
    let mut s = Vec::new();
    if chars & 0x20000000 != 0 {
        s.push("X");
    }
    if chars & 0x80000000 != 0 {
        s.push("R");
    }
    if chars & 0x40000000 != 0 {
        s.push("W");
    }
    if s.is_empty() {
        "-".to_string()
    } else {
        s.join("")
    }
}

fn read_cstr(data: &[u8], off: usize) -> String {
    if off >= data.len() {
        return String::new();
    }
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[off..end]).into_owned()
}

/// Well-known ordinal exports for DLLs that historically import by ordinal.
/// ws2_32 exports everything by ordinal; oleaut32 ships many ordinals too.
/// Names follow the Microsoft SDK headers (winsock2.h, oleauto.h).
fn well_known_ordinal(module: &str, ord: u32) -> Option<&'static str> {
    let m = module.to_ascii_lowercase();
    let m = m.trim_end_matches(".dll");
    match m {
        "ws2_32" | "wsock32" => ws2_32_map().get(&ord).copied(),
        "oleaut32" => oleaut32_map().get(&ord).copied(),
        _ => None,
    }
}

fn ws2_32_map() -> std::collections::HashMap<u32, &'static str> {
    [
        (1, "accept"),
        (2, "bind"),
        (3, "closesocket"),
        (4, "connect"),
        (5, "getpeername"),
        (6, "getsockname"),
        (7, "getsockopt"),
        (8, "htonl"),
        (9, "htons"),
        (10, "ioctlsocket"),
        (11, "inet_addr"),
        (12, "inet_ntoa"),
        (13, "listen"),
        (14, "ntohl"),
        (15, "ntohs"),
        (16, "recv"),
        (17, "recvfrom"),
        (18, "select"),
        (19, "send"),
        (20, "sendto"),
        (21, "setsockopt"),
        (22, "shutdown"),
        (23, "socket"),
        (24, "GetAddrInfoW"),
        (25, "GetNameInfoW"),
        (26, "WSApSetPostRoutine"),
        (27, "FreeAddrInfoW"),
        (28, "WPUCompleteOverlappedRequest"),
        (29, "WSAAccept"),
        (30, "WSAAddressToStringA"),
        (31, "WSAAddressToStringW"),
        (32, "WSACleanup"),
        (33, "WSACloseEvent"),
        (34, "WSAConnect"),
        (35, "WSACreateEvent"),
        (36, "WSADuplicateSocketA"),
        (37, "WSADuplicateSocketW"),
        (38, "WSAEnumNameSpaceProvidersA"),
        (39, "WSAEnumNameSpaceProvidersW"),
        (40, "WSAEnumNetworkEvents"),
        (41, "WSAEnumProtocolsA"),
        (42, "WSAEnumProtocolsW"),
        (43, "WSAEventSelect"),
        (44, "WSAGetLastError"),
        (45, "WSAGetOverlappedResult"),
        (46, "WSAGetQOSByName"),
        (47, "WSAGetServiceClassInfoA"),
        (48, "WSAGetServiceClassInfoW"),
        (49, "WSAGetServiceClassNameByClassIdA"),
        (50, "WSAGetServiceClassNameByClassIdW"),
        (51, "WSAHtonl"),
        (52, "WSAHtons"),
        (53, "WSAInstallServiceClassA"),
        (54, "WSAInstallServiceClassW"),
        (55, "WSAIoctl"),
        (56, "WSAJoinLeaf"),
        (57, "WSALookupServiceBeginA"),
        (58, "WSALookupServiceBeginW"),
        (59, "WSALookupServiceEnd"),
        (60, "WSALookupServiceNextA"),
        (61, "WSALookupServiceNextW"),
        (62, "WSANSPIoctl"),
        (63, "WSANtohl"),
        (64, "WSANtohs"),
        (65, "WSAProviderConfigChange"),
        (66, "WSARecv"),
        (67, "WSARecvDisconnect"),
        (68, "WSARecvFrom"),
        (69, "WSAResetEvent"),
        (70, "WSASend"),
        (71, "WSASendDisconnect"),
        (72, "WSASendTo"),
        (73, "WSASetEvent"),
        (74, "WSASetLastError"),
        (75, "WSASocketA"),
        (76, "WSASocketW"),
        (77, "WSAStringToAddressA"),
        (78, "WSAStringToAddressW"),
        (79, "WSAWaitForMultipleEvents"),
        (80, "WSCDeinstallProvider"),
        (81, "WSCEnableNSProvider"),
        (82, "WSCEnumProtocols"),
        (83, "WSCGetProviderPath"),
        (84, "WSCInstallProvider"),
        (85, "WSCUpdateProvider"),
        (86, "WSCWriteProviderOrder"),
        (87, "WSCInstallQOSTemplate"),
        (88, "WSCRemoveQOSTemplate"),
        (89, "WSAAsyncSelect"),
        (90, "WSAAsyncGetHostByAddr"),
        (91, "WSAAsyncGetHostByName"),
        (92, "WSAAsyncGetProtoByNumber"),
        (93, "WSAAsyncGetProtoByName"),
        (94, "WSAAsyncGetServByPort"),
        (95, "WSAAsyncGetServByName"),
        (96, "WSACancelAsyncRequest"),
        (97, "WSASetBlockingHook"),
        (98, "WSAUnhookBlockingHook"),
        (99, "WSAGetBlockingHook"),
        (100, "WSACancelBlockingCall"),
        (101, "WSAIsBlocking"),
        (101, "WSAIsBlocking"),
        (102, "WSAStartup"),
        (103, "WSACleanup"),
        (104, "WSASetServiceA"),
        (105, "WSASetServiceW"),
        (106, "WSAGetAcceptExSockaddrs"),
        (107, "WSAAddressToStringA"),
        (111, "WsControl"),
        (112, "WSARecvEx"),
        (113, "WSAConnectByList"),
        (114, "WSAConnectByNameA"),
        (115, "WSAConnectByNameW"),
        (116, "WSADuplicateSocketA"),
        (117, "WSADuplicateSocketW"),
        (118, "WSAEnumNameSpaceProvidersExA"),
        (119, "WSAEnumNameSpaceProvidersExW"),
        (120, "WSASendMsg"),
        (121, "GetAddrInfoExW"),
        (122, "SetAddrInfoExW"),
        (123, "GetAddrInfoExCancel"),
        (124, "GetAddrInfoExOverlappedResult"),
        (151, "WEP"),
        (500, "WSAJoinLeaf"),
        (501, "WSARecvEx"),
        (502, "WSARecvEx"),
        (503, "TransmitFile"),
        (504, "AcceptEx"),
        (505, "EnumProtocolsA"),
        (506, "EnumProtocolsW"),
        (507, "GetAddressByNameA"),
        (508, "GetAddressByNameW"),
        (509, "GetNameByTypeA"),
        (510, "GetNameByTypeW"),
        (511, "GetTypeByNameA"),
        (512, "GetTypeByNameW"),
        (513, "SetServiceA"),
        (514, "SetServiceW"),
        (515, "GetServiceA"),
        (516, "GetServiceW"),
        (517, "NPLoadNameSpaces"),
        (518, "NSPStartup"),
    ]
    .into_iter()
    .collect()
}

fn oleaut32_map() -> std::collections::HashMap<u32, &'static str> {
    [
        (2, "SysAllocString"),
        (3, "SysReAllocString"),
        (4, "SysAllocStringLen"),
        (5, "SysReAllocStringLen"),
        (6, "SysFreeString"),
        (7, "SysStringLen"),
        (8, "SysStringByteLen"),
        (9, "SysAllocStringByteLen"),
        (10, "SysStringLen"),
        (12, "VariantInit"),
        (13, "VariantClear"),
        (14, "VariantCopy"),
        (15, "VariantCopyInd"),
        (16, "VariantChangeType"),
        (17, "VariantChangeTypeEx"),
        (18, "VarUI1FromI2"),
        (19, "VarUI1FromI4"),
        (20, "VarUI1FromR4"),
        (21, "VarUI1FromR8"),
        (22, "VarUI1FromCy"),
        (23, "VarUI1FromDate"),
        (24, "VarUI1FromStr"),
        (25, "VarUI1FromDisp"),
        (26, "VarUI1FromBool"),
        (27, "VarUI1FromI1"),
        (28, "VarUI1FromUI2"),
        (29, "VarUI1FromUI4"),
        (30, "VarUI1FromUI8"),
        (31, "VarUI1FromDec"),
        (32, "VarUI1FromI8"),
        (34, "VarI2FromUI1"),
        (35, "VarI2FromI4"),
        (36, "VarI2FromR4"),
        (37, "VarI2FromR8"),
        (38, "VarI2FromCy"),
        (39, "VarI2FromDate"),
        (40, "VarI2FromStr"),
        (41, "VarI2FromDisp"),
        (42, "VarI2FromBool"),
        (43, "VarI2FromI1"),
        (44, "VarI2FromUI2"),
        (45, "VarI2FromUI4"),
        (46, "VarI2FromUI8"),
        (47, "VarI2FromDec"),
        (48, "VarI2FromI8"),
        (50, "VarI4FromUI1"),
        (51, "VarI4FromI2"),
        (52, "VarI4FromR4"),
        (53, "VarI4FromR8"),
        (54, "VarI4FromCy"),
        (55, "VarI4FromDate"),
        (56, "VarI4FromStr"),
        (57, "VarI4FromDisp"),
        (58, "VarI4FromBool"),
        (59, "VarI4FromI1"),
        (60, "VarI4FromUI2"),
        (61, "VarI4FromUI4"),
        (62, "VarI4FromUI8"),
        (63, "VarI4FromDec"),
        (64, "VarI4FromI8"),
        (66, "VarR4FromUI1"),
        (67, "VarR4FromI2"),
        (68, "VarR4FromI4"),
        (69, "VarR4FromR8"),
        (70, "VarR4FromCy"),
        (71, "VarR4FromDate"),
        (72, "VarR4FromStr"),
        (73, "VarR4FromDisp"),
        (74, "VarR4FromBool"),
        (75, "VarR4FromI1"),
        (76, "VarR4FromUI2"),
        (77, "VarR4FromUI4"),
        (78, "VarR4FromUI8"),
        (79, "VarR4FromDec"),
        (80, "VarR4FromI8"),
        (82, "VarR8FromUI1"),
        (83, "VarR8FromI2"),
        (84, "VarR8FromI4"),
        (85, "VarR8FromR4"),
        (86, "VarR8FromCy"),
        (87, "VarR8FromDate"),
        (88, "VarR8FromStr"),
        (89, "VarR8FromDisp"),
        (90, "VarR8FromBool"),
        (91, "VarR8FromI1"),
        (92, "VarR8FromUI2"),
        (93, "VarR8FromUI4"),
        (94, "VarR8FromUI8"),
        (95, "VarR8FromDec"),
        (96, "VarR8FromI8"),
        (98, "VarDateFromUI1"),
        (99, "VarDateFromI2"),
        (100, "VarDateFromI4"),
        (101, "VarDateFromR4"),
        (102, "VarDateFromR8"),
        (103, "VarDateFromCy"),
        (104, "VarDateFromStr"),
        (105, "VarDateFromDisp"),
        (106, "VarDateFromBool"),
        (107, "VarDateFromI1"),
        (108, "VarDateFromUI2"),
        (109, "VarDateFromUI4"),
        (110, "VarDateFromUI8"),
        (111, "VarDateFromDec"),
        (112, "VarDateFromI8"),
        (114, "VarCyFromUI1"),
        (115, "VarCyFromI2"),
        (116, "VarCyFromI4"),
        (117, "VarCyFromR4"),
        (118, "VarCyFromR8"),
        (119, "VarCyFromDate"),
        (120, "VarCyFromStr"),
        (121, "VarCyFromDisp"),
        (122, "VarCyFromBool"),
        (123, "VarCyFromI1"),
        (124, "VarCyFromUI2"),
        (125, "VarCyFromUI4"),
        (126, "VarCyFromUI8"),
        (127, "VarCyFromDec"),
        (128, "VarCyFromI8"),
        (130, "VarBstrFromUI1"),
        (131, "VarBstrFromI2"),
        (132, "VarBstrFromI4"),
        (133, "VarBstrFromR4"),
        (134, "VarBstrFromR8"),
        (135, "VarBstrFromCy"),
        (136, "VarBstrFromDate"),
        (137, "VarBstrFromDisp"),
        (138, "VarBstrFromBool"),
        (139, "VarBstrFromI1"),
        (140, "VarBstrFromUI2"),
        (141, "VarBstrFromUI4"),
        (142, "VarBstrFromUI8"),
        (143, "VarBstrFromDec"),
        (144, "VarBstrFromI8"),
        (146, "VarBoolFromUI1"),
        (147, "VarBoolFromI2"),
        (148, "VarBoolFromI4"),
        (149, "VarBoolFromR4"),
        (150, "VarBoolFromR8"),
        (151, "VarBoolFromCy"),
        (152, "VarBoolFromDate"),
        (153, "VarBoolFromStr"),
        (154, "VarBoolFromDisp"),
        (155, "VarBoolFromI1"),
        (156, "VarBoolFromUI2"),
        (157, "VarBoolFromUI4"),
        (158, "VarBoolFromUI8"),
        (159, "VarBoolFromDec"),
        (160, "VarBoolFromI8"),
        (162, "VarI1FromUI1"),
        (163, "VarI1FromI2"),
        (164, "VarI1FromI4"),
        (165, "VarI1FromR4"),
        (166, "VarI1FromR8"),
        (167, "VarI1FromCy"),
        (168, "VarI1FromDate"),
        (169, "VarI1FromStr"),
        (170, "VarI1FromDisp"),
        (171, "VarI1FromBool"),
        (172, "VarI1FromUI2"),
        (173, "VarI1FromUI4"),
        (174, "VarI1FromUI8"),
        (175, "VarI1FromDec"),
        (176, "VarI1FromI8"),
        (178, "VarUI2FromUI1"),
        (179, "VarUI2FromI2"),
        (180, "VarUI2FromI4"),
        (181, "VarUI2FromR4"),
        (182, "VarUI2FromR8"),
        (183, "VarUI2FromCy"),
        (184, "VarUI2FromDate"),
        (185, "VarUI2FromStr"),
        (186, "VarUI2FromDisp"),
        (187, "VarUI2FromBool"),
        (188, "VarUI2FromI1"),
        (189, "VarUI2FromUI4"),
        (190, "VarUI2FromUI8"),
        (191, "VarUI2FromDec"),
        (192, "VarUI2FromI8"),
        (194, "VarUI4FromUI1"),
        (195, "VarUI4FromI2"),
        (196, "VarUI4FromI4"),
        (197, "VarUI4FromR4"),
        (198, "VarUI4FromR8"),
        (199, "VarUI4FromCy"),
        (200, "VarUI4FromDate"),
        (201, "VarUI4FromStr"),
        (202, "VarUI4FromDisp"),
        (203, "VarUI4FromBool"),
        (204, "VarUI4FromI1"),
        (205, "VarUI4FromUI2"),
        (206, "VarUI4FromUI8"),
        (207, "VarUI4FromDec"),
        (208, "VarUI4FromI8"),
        (210, "VarUI8FromUI1"),
        (211, "VarUI8FromI2"),
        (212, "VarUI8FromI4"),
        (213, "VarUI8FromR4"),
        (214, "VarUI8FromR8"),
        (215, "VarUI8FromCy"),
        (216, "VarUI8FromDate"),
        (217, "VarUI8FromStr"),
        (218, "VarUI8FromDisp"),
        (219, "VarUI8FromBool"),
        (220, "VarUI8FromI1"),
        (221, "VarUI8FromUI2"),
        (222, "VarUI8FromUI4"),
        (223, "VarUI8FromDec"),
        (224, "VarUI8FromI8"),
        (226, "VarDecFromUI1"),
        (227, "VarDecFromI2"),
        (228, "VarDecFromI4"),
        (229, "VarDecFromR4"),
        (230, "VarDecFromR8"),
        (231, "VarDecFromCy"),
        (232, "VarDecFromDate"),
        (233, "VarDecFromStr"),
        (234, "VarDecFromDisp"),
        (235, "VarDecFromBool"),
        (236, "VarDecFromI1"),
        (237, "VarDecFromUI2"),
        (238, "VarDecFromUI4"),
        (239, "VarDecFromUI8"),
        (240, "VarDecFromI8"),
        (242, "VarDecFromI8"),
        (243, "VarDecFromUI8"),
        (244, "VarDecFromI1"),
        (246, "SafeArrayAllocDescriptor"),
        (247, "SafeArrayAllocDescriptorEx"),
        (248, "SafeArrayAllocData"),
        (249, "SafeArrayCreateVector"),
        (250, "SafeArrayCreate"),
        (251, "SafeArrayCreateEx"),
        (253, "SafeArrayDestroyDescriptor"),
        (254, "SafeArrayDestroyData"),
        (255, "SafeArrayDestroy"),
        (256, "SafeArrayRedim"),
        (257, "SafeArrayGetDim"),
        (258, "SafeArrayGetElemsize"),
        (259, "SafeArrayGetUBound"),
        (260, "SafeArrayGetLBound"),
        (261, "SafeArrayLock"),
        (262, "SafeArrayUnlock"),
        (263, "SafeArrayAccessData"),
        (264, "SafeArrayUnaccessData"),
        (265, "SafeArrayGetElement"),
        (266, "SafeArrayPutElement"),
        (267, "SafeArrayCopy"),
        (268, "SafeArrayCopyData"),
        (269, "SafeArrayGetRecordInfo"),
        (270, "SafeArraySetRecordInfo"),
        (271, "SafeArrayCreateVectorEx"),
        (273, "SafeArraySetRecordInfo"),
        (277, "SafeArrayGetVartype"),
        (281, "SafeArrayCreateEx"),
        (291, "VarFormat"),
        (292, "VarDateFromI2"),
        (293, "VarFormatNumber"),
        (295, "VarFormatDate"),
        (297, "VarFormatCurrency"),
        (303, "VarWeekdayName"),
        (304, "VarDateFromI2"),
        (307, "VarFormatPercent"),
        (308, "VarFormatDateTime"),
        (311, "VarMonthName"),
        (315, "SafeArrayGetLBound"),
        (317, "VarCyFromI4"),
        (319, "VarCyFromR8"),
        (320, "VarCyAdd"),
        (321, "VarCyMul"),
        (322, "VarCyMulI4"),
        (323, "VarCySub"),
        (324, "VarCyAbs"),
        (325, "VarCyFix"),
        (326, "VarCyInt"),
        (327, "VarCyNeg"),
        (328, "VarCyRound"),
        (329, "VarCyCmp"),
        (330, "VarCyCmpR8"),
        (331, "VarCyFloor"),
        (332, "VarCyCeil"),
        (331, "VarCyFloor"),
        (332, "VarCyCeil"),
        (333, "VarBstrCat"),
        (334, "VarBstrCmp"),
        (335, "VarR8Pow"),
        (336, "VarR8Sqrt"),
        (337, "VarR8Round"),
        (338, "VarR8Round"),
        (339, "VarNot"),
        (340, "VarNot"),
        (341, "VarNot"),
        (342, "VarNot"),
        (343, "VarNot"),
        (344, "VarNot"),
        (345, "VarNot"),
        (346, "VarNot"),
        (347, "VarR4CmpR8"),
        (348, "VarR8Round"),
        (349, "VarCyMulI4"),
        (350, "VarCyMulI8"),
        (351, "VarCyAdd"),
        (352, "VarCySub"),
        (353, "VarCyCmpR8"),
        (355, "VarUI1FromI2"),
        (356, "VarI2FromUI1"),
        (357, "VarUI1FromI4"),
        (358, "VarI4FromUI1"),
        (364, "VariantChangeType"),
        (365, "VariantChangeType"),
        (366, "VariantChangeType"),
        (367, "VariantChangeType"),
        (368, "VariantChangeType"),
        (369, "VariantChangeType"),
        (370, "VariantChangeType"),
        (371, "VariantChangeType"),
        (372, "VariantChangeType"),
        (373, "VariantChangeType"),
        (374, "VariantChangeType"),
        (375, "VariantChangeType"),
        (376, "VariantChangeType"),
        (377, "VariantChangeType"),
        (378, "VariantChangeType"),
        (379, "VariantChangeType"),
        (380, "VariantChangeType"),
        (381, "VariantChangeType"),
        (382, "VariantChangeType"),
        (383, "VariantChangeType"),
        (384, "VariantChangeType"),
        (385, "VariantChangeType"),
        (386, "VariantChangeType"),
        (387, "VariantChangeType"),
        (388, "VariantChangeType"),
        (389, "VariantChangeType"),
        (390, "VariantChangeType"),
        (391, "VariantChangeType"),
        (392, "VariantChangeType"),
        (393, "VariantChangeType"),
        (394, "VariantChangeType"),
        (395, "VariantChangeType"),
        (396, "VariantChangeType"),
        (397, "VariantChangeType"),
        (398, "VariantChangeType"),
        (399, "VariantChangeType"),
        (400, "VariantChangeType"),
        (401, "VariantChangeType"),
        (402, "VariantChangeType"),
        (403, "VariantChangeType"),
        (404, "VariantChangeType"),
        (405, "VariantChangeType"),
        (406, "VariantChangeType"),
        (407, "VariantChangeType"),
        (408, "VariantChangeType"),
        (409, "VariantChangeType"),
        (410, "VariantChangeType"),
        (411, "VariantChangeType"),
        (412, "VariantChangeType"),
        (413, "VariantChangeType"),
        (414, "VariantChangeType"),
        (415, "VariantChangeType"),
        (416, "VariantChangeType"),
        (417, "VariantChangeType"),
        (418, "VariantChangeType"),
        (419, "VariantChangeType"),
        (420, "VariantChangeType"),
        (421, "VariantChangeType"),
        (422, "VariantChangeType"),
        (423, "VariantChangeType"),
        (424, "VariantChangeType"),
        (425, "VariantChangeType"),
        (426, "VariantChangeType"),
        (427, "VariantChangeType"),
        (428, "VariantChangeType"),
        (429, "VariantChangeType"),
        (430, "VariantChangeType"),
        (431, "VariantChangeType"),
        (432, "VariantChangeType"),
        (433, "VariantChangeType"),
        (434, "VariantChangeType"),
        (435, "VariantChangeType"),
        (436, "VariantChangeType"),
        (437, "VariantChangeType"),
        (438, "VariantChangeType"),
        (439, "VariantChangeType"),
        (440, "VariantChangeType"),
        (441, "VariantChangeType"),
        (442, "VariantChangeType"),
        (443, "VariantChangeType"),
        (444, "VariantChangeType"),
        (445, "VariantChangeType"),
        (446, "VariantChangeType"),
        (447, "VariantChangeType"),
        (448, "VariantChangeType"),
        (449, "VariantChangeType"),
        (450, "VariantChangeType"),
        (451, "VariantChangeType"),
        (452, "VariantChangeType"),
        (453, "VariantChangeType"),
        (454, "VariantChangeType"),
        (455, "VariantChangeType"),
        (456, "VariantChangeType"),
        (457, "VariantChangeType"),
        (458, "VariantChangeType"),
        (459, "VariantChangeType"),
        (460, "VariantChangeType"),
        (461, "VariantChangeType"),
        (462, "VariantChangeType"),
        (463, "VariantChangeType"),
        (464, "VariantChangeType"),
        (465, "VariantChangeType"),
        (466, "VariantChangeType"),
        (467, "VariantChangeType"),
        (468, "VariantChangeType"),
        (469, "VariantChangeType"),
        (470, "VariantChangeType"),
        (471, "VariantChangeType"),
        (472, "VariantChangeType"),
        (473, "VariantChangeType"),
        (474, "VariantChangeType"),
        (475, "VariantChangeType"),
        (476, "VariantChangeType"),
        (477, "VariantChangeType"),
        (478, "VariantChangeType"),
        (479, "VariantChangeType"),
        (480, "VariantChangeType"),
        (481, "VariantChangeType"),
        (482, "VariantChangeType"),
        (483, "VariantChangeType"),
        (484, "VariantChangeType"),
        (485, "VariantChangeType"),
        (486, "VariantChangeType"),
        (487, "VariantChangeType"),
        (488, "VariantChangeType"),
        (489, "VariantChangeType"),
        (490, "VariantChangeType"),
        (491, "VariantChangeType"),
        (492, "VariantChangeType"),
        (493, "VariantChangeType"),
        (494, "VariantChangeType"),
        (495, "VariantChangeType"),
        (496, "VariantChangeType"),
        (497, "VariantChangeType"),
        (498, "VariantChangeType"),
        (499, "VariantChangeType"),
        (500, "VariantChangeType"),
    ]
    .into_iter()
    .filter(|(o, _)| *o <= 500)
    .collect()
}

/// Parse the RT_VERSION resource (VS_VERSIONINFO) into key/value pairs.
/// We walk the resource directory entries to the first version-data leaf,
/// then scan the leaf for StringFileInfo blocks (UTF-16 key/value pairs).
/// One node of the PE resource tree (`.rsrc` section).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResourceEntry {
    /// tree depth: 1 = type, 2 = name, 3 = language, leaf data is attached at 3
    pub level: u8,
    /// numeric id or resource name (named entries)
    pub id: String,
    /// RT_* type name for level-1 entries (CURSOR, BITMAP, VERSION, ...)
    pub type_name: Option<String>,
    /// file offset of the data (leaf) or None (directory)
    pub offset: Option<u64>,
    /// data size in bytes (leaf)
    pub size: Option<u64>,
    /// RVA of the data (leaf)
    pub rva: Option<u64>,
    /// language id for language-level entries
    pub lang: Option<u32>,
}

/// Standard RT_* type names (winuser.h).
fn rt_type_name(id: u32) -> &'static str {
    match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        _ => "",
    }
}

/// Walk the whole PE resource directory tree (depth-first, level <= 3),
/// emitting one ResourceEntry per directory entry and per data leaf.
pub fn parse_resource_tree(
    data: &[u8],
    opt: usize,
    is64: bool,
    sections: &[Section],
    size_of_headers: u32,
) -> Vec<ResourceEntry> {
    let mut out = Vec::new();
    // data directory index 2 = resources
    let dd = opt + if is64 { 112 } else { 96 };
    if dd + 3 * 8 > data.len() {
        return out;
    }
    let rva = u32::from_le_bytes(data[dd + 2 * 8..dd + 2 * 8 + 4].try_into().unwrap());
    if rva == 0 {
        return out;
    }
    let Some(dir_off) = rva_to_offset_rva(rva, sections, size_of_headers as u64) else {
        return out;
    };

    // decode a named-entry UTF-16 string; None for plain id entries
    fn read_dir_name(data: &[u8], dir_off: usize, name_field: u32) -> Option<String> {
        if name_field & 0x8000_0000 == 0 {
            return None;
        }
        let no = dir_off + (name_field & 0x7fff_ffff) as usize;
        if no + 2 > data.len() {
            return None;
        }
        let len = u16::from_le_bytes(data[no..no + 2].try_into().unwrap()) as usize;
        if no + 2 + len * 2 > data.len() {
            return None;
        }
        let units: Vec<u16> = (0..len)
            .map(|i| u16::from_le_bytes([data[no + 2 + i * 2], data[no + 3 + i * 2]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    fn walk(
        data: &[u8],
        dir_off: usize,
        cur: usize,
        level: u8,
        sections: &[Section],
        size_of_headers: u32,
        out: &mut Vec<ResourceEntry>,
    ) {
        if level > 3 || cur + 16 > data.len() {
            return;
        }
        let named = u16::from_le_bytes(data[cur + 12..cur + 14].try_into().unwrap()) as usize;
        let ids = u16::from_le_bytes(data[cur + 14..cur + 16].try_into().unwrap()) as usize;
        for e in 0..named + ids {
            let eh = cur + 16 + e * 8;
            if eh + 8 > data.len() {
                break;
            }
            let name_field = u32::from_le_bytes(data[eh..eh + 4].try_into().unwrap());
            let val = u32::from_le_bytes(data[eh + 4..eh + 8].try_into().unwrap());
            let is_named = name_field & 0x8000_0000 != 0;
            let name = read_dir_name(data, dir_off, name_field)
                .unwrap_or_else(|| format!("{}", name_field & 0xffff));
            if val & 0x8000_0000 != 0 {
                // subdirectory
                let type_name = if level == 1 && !is_named {
                    let t = rt_type_name(name_field & 0xffff);
                    if t.is_empty() {
                        None
                    } else {
                        Some(t.to_string())
                    }
                } else {
                    None
                };
                let lang = if level == 3 {
                    name.parse::<u32>().ok()
                } else {
                    None
                };
                out.push(ResourceEntry {
                    level,
                    id: name,
                    type_name,
                    offset: None,
                    size: None,
                    rva: None,
                    lang,
                });
                walk(
                    data,
                    dir_off,
                    dir_off + (val & 0x7fff_ffff) as usize,
                    level + 1,
                    sections,
                    size_of_headers,
                    out,
                );
            } else {
                // leaf: IMAGE_RESOURCE_DATA_ENTRY at dir_off + val
                let lh = dir_off + val as usize;
                if lh + 16 > data.len() {
                    break;
                }
                let data_rva = u32::from_le_bytes(data[lh..lh + 4].try_into().unwrap());
                let dsize = u32::from_le_bytes(data[lh + 4..lh + 8].try_into().unwrap());
                let off = rva_to_offset_rva(data_rva, sections, size_of_headers as u64);
                // the data leaf lives at the language level (3); its id IS
                // the language id, so emit it as the level-3 entry itself
                let lang = if level == 3 {
                    name.parse::<u32>().ok()
                } else {
                    None
                };
                out.push(ResourceEntry {
                    level,
                    id: name,
                    type_name: None,
                    offset: off.map(|o| o as u64),
                    size: Some(dsize as u64),
                    rva: Some(data_rva as u64),
                    lang,
                });
            }
        }
    }

    walk(
        data,
        dir_off,
        dir_off,
        1,
        sections,
        size_of_headers,
        &mut out,
    );
    out
}

/// Parse the .NET (CLR) header from COM descriptor data directory 14.
fn parse_dotnet(
    data: &[u8],
    opt: usize,
    is64: bool,
    sections: &[Section],
    size_of_headers: u32,
) -> Option<DotNetInfo> {
    let dd = opt + if is64 { 112 } else { 96 };
    const COM_DESC: usize = 14;
    if dd + (COM_DESC + 1) * 8 > data.len() {
        return None;
    }
    let rva = u32::from_le_bytes(
        data[dd + COM_DESC * 8..dd + COM_DESC * 8 + 4]
            .try_into()
            .unwrap(),
    );
    let size = u32::from_le_bytes(
        data[dd + COM_DESC * 8 + 4..dd + COM_DESC * 8 + 8]
            .try_into()
            .unwrap(),
    );
    if rva == 0 || size < 72 {
        return None;
    }
    let off = rva_to_offset_rva(rva, sections, size_of_headers as u64)?;
    if off + 72 > data.len() {
        return None;
    }
    // IMAGE_COR20_HEADER: cb, MajorRuntimeVersion, MinorRuntimeVersion,
    // MetaData (RVA+Size), Flags, EntryPointToken, Resources, StrongName...
    let major = u16::from_le_bytes(data[off + 4..off + 6].try_into().unwrap());
    let minor = u16::from_le_bytes(data[off + 6..off + 8].try_into().unwrap());
    let md_rva = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as u64;
    let md_size = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap()) as u64;
    let flags = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
    let entry = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
    let runtime_version = match (major, minor) {
        (1, 0) => "v1.0.3705".to_string(),
        (1, 1) => "v1.1.4322".to_string(),
        (2, n) if n < 50 => "v2.0.50727".to_string(),
        (4, _) => "v4.0.30319".to_string(),
        _ => format!("v{major}.{minor}"),
    };
    let mut flag_names: Vec<&'static str> = Vec::new();
    if flags & 0x1 != 0 {
        flag_names.push("ILONLY");
    }
    if flags & 0x2 != 0 {
        flag_names.push("32BITREQUIRED");
    }
    if flags & 0x4 != 0 {
        flag_names.push("IL_LIBRARY");
    }
    if flags & 0x8 != 0 {
        flag_names.push("STRONGNAMESIGNED");
    }
    if flags & 0x10 != 0 {
        flag_names.push("NATIVE_ENTRYPOINT");
    }
    if flags & 0x0002_0000 != 0 {
        flag_names.push("32BITPREFERRED");
    }
    Some(DotNetInfo {
        runtime_version,
        flags: if flag_names.is_empty() {
            format!("{flags:#x}")
        } else {
            flag_names.join("|")
        },
        metadata_rva: md_rva,
        metadata_size: md_size,
        entry_point_token: format!("{entry:#010x}"),
    })
}

fn parse_version_info(
    data: &[u8],
    pe_off: usize,
    opt: usize,
    is64: bool,
    sections: &[Section],
    size_of_headers: u32,
) -> Vec<(String, String)> {
    // data directory table starts at opt + 96 (PE32) / opt + 112 (PE64);
    // directory index 2 = resources. RT_VERSION is resource *type* 16 inside.
    let dd = opt + if is64 { 112 } else { 96 };
    const RESOURCE_DIR: usize = 2;
    let need = dd + (RESOURCE_DIR + 1) * 8;
    if need > data.len() {
        return Vec::new();
    }
    let rva = u32::from_le_bytes(
        data[dd + RESOURCE_DIR * 8..dd + RESOURCE_DIR * 8 + 4]
            .try_into()
            .unwrap(),
    );
    let mut size = u32::from_le_bytes(
        data[dd + RESOURCE_DIR * 8 + 4..dd + RESOURCE_DIR * 8 + 8]
            .try_into()
            .unwrap(),
    );
    if rva == 0 || size == 0 {
        return Vec::new();
    }
    let dir_off = match rva_to_offset_rva(rva, sections, size_of_headers as u64) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let _ = pe_off;
    // Level 1 of the resource tree lists types; find RT_VERSION (ID 16)
    // and descend name/lang levels to its first data leaf.
    let mut leaf: Option<usize> = None;
    if dir_off + 16 > data.len() {
        return Vec::new();
    }
    let l1_named =
        u16::from_le_bytes(data[dir_off + 12..dir_off + 14].try_into().unwrap()) as usize;
    let l1_ids = u16::from_le_bytes(data[dir_off + 14..dir_off + 16].try_into().unwrap()) as usize;
    'types: for e in 0..l1_named + l1_ids {
        let eh = dir_off + 16 + e * 8;
        if eh + 8 > data.len() {
            break 'types;
        }
        let name_or_id = u32::from_le_bytes(data[eh..eh + 4].try_into().unwrap());
        let entry_val = u32::from_le_bytes(data[eh + 4..eh + 8].try_into().unwrap());
        // named entries have the high bit set on the name field
        if name_or_id & 0x8000_0000 != 0 {
            continue; // named type, not RT_VERSION
        }
        if name_or_id != 16 || entry_val & 0x8000_0000 == 0 {
            continue;
        }
        // level 2: names under RT_VERSION
        let l2 = dir_off + (entry_val & 0x7fff_ffff) as usize;
        if l2 + 16 > data.len() {
            break 'types;
        }
        let l2_total = u16::from_le_bytes(data[l2 + 12..l2 + 14].try_into().unwrap()) as usize
            + u16::from_le_bytes(data[l2 + 14..l2 + 16].try_into().unwrap()) as usize;
        'names: for e2 in 0..l2_total {
            let eh2 = l2 + 16 + e2 * 8;
            if eh2 + 8 > data.len() {
                break 'names;
            }
            let v2 = u32::from_le_bytes(data[eh2 + 4..eh2 + 8].try_into().unwrap());
            if v2 & 0x8000_0000 == 0 {
                continue;
            }
            // level 3: languages
            let l3 = dir_off + (v2 & 0x7fff_ffff) as usize;
            if l3 + 16 > data.len() {
                break 'names;
            }
            let l3_total = u16::from_le_bytes(data[l3 + 12..l3 + 14].try_into().unwrap()) as usize
                + u16::from_le_bytes(data[l3 + 14..l3 + 16].try_into().unwrap()) as usize;
            'langs: for e3 in 0..l3_total {
                let eh3 = l3 + 16 + e3 * 8;
                if eh3 + 8 > data.len() {
                    break 'langs;
                }
                let v3 = u32::from_le_bytes(data[eh3 + 4..eh3 + 8].try_into().unwrap());
                if v3 & 0x8000_0000 != 0 {
                    continue;
                }
                let lh = dir_off + v3 as usize; // IMAGE_RESOURCE_DATA_ENTRY
                if lh + 16 > data.len() {
                    break 'langs;
                }
                // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(+0), Size(+4), CodePage(+8)
                let data_rva = u32::from_le_bytes(data[lh..lh + 4].try_into().unwrap());
                let dsize = u32::from_le_bytes(data[lh + 4..lh + 8].try_into().unwrap());
                if let Some(off) = rva_to_offset_rva(data_rva, sections, size_of_headers as u64) {
                    leaf = Some(off);
                    size = dsize;
                }
                break 'langs;
            }
            if leaf.is_some() {
                break 'names;
            }
        }
        if leaf.is_some() {
            break 'types;
        }
    }
    let Some(leaf_off) = leaf else {
        return Vec::new();
    };
    let end = (leaf_off + size as usize).min(data.len());
    let blob = &data[leaf_off.min(data.len())..end];

    // VS_VERSIONINFO: sequence of UTF-16 strings; the StringFileInfo section
    // holds "Key\0Value" pairs. Strategy: decode the whole blob as UTF-16LE,
    // then take known keys and the word that follows each.
    let units: Vec<u16> = blob
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let mut words: Vec<String> = Vec::new();
    let mut cur_w = String::new();
    let mut i = 0usize;
    while i < units.len() {
        let u = units[i];
        if u == 0 {
            if !cur_w.is_empty() {
                words.push(std::mem::take(&mut cur_w));
            }
            i += 1;
            continue;
        }
        // keep only characters that look like version-info content
        if (0x20..0x7f).contains(&u) || (0xa0..0x24f).contains(&u) {
            if let Some(c) = char::from_u32(u as u32) {
                cur_w.push(c);
                i += 1;
                continue;
            }
        }
        if !cur_w.is_empty() {
            words.push(std::mem::take(&mut cur_w));
        }
        i += 1;
    }
    if !cur_w.is_empty() {
        words.push(cur_w);
    }
    const KEYS: [&str; 12] = [
        "CompanyName",
        "FileDescription",
        "FileVersion",
        "InternalName",
        "LegalCopyright",
        "LegalTrademarks",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
        "Comments",
        "PrivateBuild",
        "SpecialBuild",
    ];
    let mut out = Vec::new();
    for w in 0..words.len() {
        for k in KEYS {
            if words[w] == k && w + 1 < words.len() {
                out.push((k.to_string(), words[w + 1].clone()));
            }
        }
    }
    out.dedup();
    out
}
