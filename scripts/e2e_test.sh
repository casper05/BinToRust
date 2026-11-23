#!/usr/bin/env bash
# Сквозной тест всех команд bin-anything на ELF и PE.
# Путь к бинарнику — env BA (по умолчанию target/release рядом со скриптом).
# Путь к реальному PE (AutoChart.exe) — env AC; без него зависимые проверки
# честно пропускаются со счётчиком SKIP и итогом «X of Y».
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# BA: env override, иначе ищем бинарник в трёх известных лейаутах:
# 1) крейт в корне репо (GitHub-лейаут)  2) крейт в подкаталоге  3) бинарник рядом со скриптом (поставка)
if [ -z "${BA:-}" ]; then
  if [ -x "$SCRIPT_DIR/../target/release/bin-anything" ]; then
    BA="$SCRIPT_DIR/../target/release/bin-anything"
  elif [ -x "$SCRIPT_DIR/bin-anything/target/release/bin-anything" ]; then
    BA="$SCRIPT_DIR/bin-anything/target/release/bin-anything"
  elif [ -x "$SCRIPT_DIR/bin-anything" ]; then
    BA="$SCRIPT_DIR/bin-anything"
  else
    BA="$SCRIPT_DIR/../target/release/bin-anything"
  fi
fi
AC="${AC:-}"
SKIP=0
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
skip() { SKIP=$((SKIP+1)); echo "SKIP: $1"; }
check() { # check <name> <expected_rc> <cmd...>
  local name="$1"; shift; local want_rc="$1"; shift
  "$@" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" -eq "$want_rc" ]; then ok "$name"; else bad "$name (rc=$rc, want $want_rc)"; fi
}
# guard <файл> <имя-набора> — общий guard для опциональных наборов
guard() { [ -n "$2" ] && [ -f "$2" ]; }

ELF=/bin/true
PE=/tmp/t.exe
DLL=/tmp/pe_dll.dll
Patched=/tmp/ba_patched.exe

# --- generate PE fixtures (no mingw needed) ---
python3 "$(dirname "$0")/make_pe_fixture.py" "$PE" "$DLL" >/dev/null 2>&1 || \
  python3 "$SCRIPT_DIR/make_pe_fixture.py" "$PE" "$DLL" >/dev/null
[ -s "$PE" ] && ok "PE fixtures generated" || bad "PE fixtures"

echo "== ELF ($ELF) =="
check "inspect" 0 $BA inspect $ELF
check "inspect --json" 0 $BA --json inspect $ELF
check "sections" 0 $BA sections $ELF
check "sections --json" 0 $BA --json sections $ELF
check "symbols" 0 $BA symbols $ELF
check "symbols --filter" 0 $BA symbols $ELF --filter error
check "symbols --kind func" 0 $BA symbols $ELF --kind func
check "imports" 0 $BA imports $ELF
check "exports" 0 $BA exports $ELF
check "strings" 0 $BA strings $ELF --min-len 8
check "strings --filter" 0 $BA strings $ELF --filter GLIBC
check "hex vaddr" 0 $BA hex $ELF 0x27e0 --len 64
check "hex offset" 0 $BA hex $ELF +0x27e0 --len 64
check "disasm vaddr" 0 $BA disasm $ELF 0x27e0 --count 10
check "disasm --json" 0 $BA --json disasm $ELF 0x27e0 --count 10
check "disasm len" 0 $BA disasm $ELF 0x27e0 --len 32
check "hash" 0 $BA hash $ELF
check "entropy" 0 $BA entropy $ELF 0x27e0 --len 512
check "bad symbol -> rc2" 2 $BA disasm $ELF nosuchsymbol12345

echo "== PE ($PE) =="
check "inspect PE" 0 $BA inspect $PE
check "sections PE" 0 $BA sections $PE
check "imports PE" 0 $BA imports $PE
check "exports PE (DLL)" 0 $BA exports $DLL
check "symbols PE" 0 $BA symbols $PE
check "disasm PE entry" 0 $BA disasm $PE 0x101000 --count 10
check "hex PE" 0 $BA hex $PE 0x101000 --len 32
check "strings PE" 0 $BA strings $PE --min-len 6
check "hash PE" 0 $BA hash $PE

echo "== modify =="
rm -f /tmp/ba_*.exe /tmp/ba_*.bin /tmp/ba_*.png /tmp/ba_snap.json
check "patch -> new file" 0 $BA patch $PE +0x600 '\x90\x90' --output $Patched
check "compare same" 0 $BA compare $PE $PE
check "compare diff (rc0)" 0 $BA compare $PE $Patched
# carve: файл с PNG
python3 -c "
import zlib, struct
def chunk(t, d):
    c = t + d
    return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB',1,1,8,2,0,0,0)) + chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00')) + chunk(b'IEND', b'')
open('/tmp/ba_carve.bin','wb').write(b'XX' + png + b'YY')
"
check "carve" 0 $BA carve /tmp/ba_carve.bin
$BA carve /tmp/ba_carve.bin --json 2>/dev/null | grep -q '"PNG"' && ok "carve finds PNG" || bad "carve PNG"
check "extract" 0 $BA extract /tmp/ba_carve.bin 0x2 71 /tmp/ba_extracted.png
python3 -c "from PIL import Image; im=Image.open('/tmp/ba_extracted.png'); im.load()" 2>/dev/null && ok "extracted PNG valid" || bad "extracted PNG valid"

echo "== behavior =="
check "run" 0 $BA run --json /bin/echo hello
check "record" 0 $BA record /bin/echo --snapshot /tmp/ba_snap.json -- hello
check "replay match" 0 $BA replay /tmp/ba_snap.json
$BA replay /tmp/ba_snap.json 2>/dev/null | grep -q "MATCH" && ok "replay says MATCH" || bad "replay MATCH"
# таймаут: sleep 5 с таймаутом 1s -> процесс убит сигналом, но инструмент отчитывается (rc 0)
$BA run /bin/sleep --timeout-secs 1 -- 5 2>/dev/null | grep -q "signal Some(9)" && ok "timeout enforced (killed)" || bad "timeout enforced"

# снимок самодостаточен: env + stdin + timeout записываются и воспроизводятся
echo -n "pat" > /tmp/ba_stdin.txt
check "record env/stdin" 0 $BA record /bin/cat --snapshot /tmp/ba_snap2.json \
  --stdin-file /tmp/ba_stdin.txt --env BA_E2E=1 --timeout-secs 5
grep -q '"stdin_data"' /tmp/ba_snap2.json && ok "snapshot embeds stdin" || bad "snapshot stdin"
grep -q '"BA_E2E=1"' /tmp/ba_snap2.json && ok "snapshot embeds env" || bad "snapshot env"
grep -q '"timeout_secs": 5' /tmp/ba_snap2.json && ok "snapshot embeds timeout" || bad "snapshot timeout"
$BA replay /tmp/ba_snap2.json 2>/dev/null | grep -q "MATCH" && ok "replay reproduces env/stdin" || bad "replay env/stdin"
# extract overflow guard: офсет, переполняющий u64 при off+size
$BA extract /bin/true 0xffffffffffffff00 0x200 /tmp/ba_ovf.bin 2>&1 | grep -qi "exceeds" && ok "extract overflow rejected" || bad "extract overflow"
# disasm: count=0 и превышение окна отклоняются с понятной ошибкой
$BA disasm /bin/true 0x1000 --count 0 2>&1 | grep -qi "count" && ok "disasm count=0 rejected" || bad "disasm count=0"
$BA disasm /bin/true 0x1000 --len 0xffffffff 2>&1 | grep -qi "window\|chunks" && ok "disasm window cap" || bad "disasm window cap"

echo "== v0.2 new features =="
# search: байтовый паттерн с wildcard (call rel32 в /bin/true)
$BA search /bin/true '\xe8????????' --max 5 2>/dev/null | grep -q "matches:" && ok "search wildcard hex" || bad "search wildcard"
$BA search /bin/true 'GLIBC' --max 5 2>/dev/null | grep -q "GLIBC" && ok "search ascii" || bad "search ascii"
$BA --json search /bin/true 'GLIBC' 2>/dev/null | grep -q '"total"\|"matches"' && ok "search json" || bad "search json"
check "search bad pattern -> rc2" 2 $BA search /bin/true '\xzz'
check "search empty -> rc2" 2 $BA search /bin/true ''
# xrefs: ссылки на функцию error в /bin/true (есть точно: call 0x2476 x3)
$BA xrefs /bin/true error 2>/dev/null | grep -q "call" && ok "xrefs by symbol" || bad "xrefs symbol"
$BA --json xrefs /bin/true 0x2476 2>/dev/null | grep -q '"xrefs_total"' && ok "xrefs json by addr" || bad "xrefs json"
# согласование с objdump: количество call на error совпадает
OD=$(objdump -d /bin/true 2>/dev/null | grep -c "call.*2476 <error")
BX=$($BA --json xrefs /bin/true error | python3 -c "import json,sys; print(json.load(sys.stdin)['by_kind']['call'])")
[ "$OD" = "$BX" ] && [ "$OD" != "0" ] && ok "xrefs match objdump ($OD calls)" || bad "xrefs vs objdump (objdump=$OD ours=$BX)"
check "xrefs bad symbol -> rc2" 2 $BA xrefs /bin/true nosuchsym123
# hash: md5/sha1 совпадают с системными утилитами
SYS_MD5=$(md5sum $ELF | cut -d' ' -f1)
OUR_MD5=$($BA hash $ELF | grep '^md5:' | awk '{print $2}')
[ "$SYS_MD5" = "$OUR_MD5" ] && ok "hash md5 matches md5sum" || bad "hash md5 ($OUR_MD5 vs $SYS_MD5)"
SYS_SHA1=$(sha1sum $ELF | cut -d' ' -f1)
OUR_SHA1=$($BA hash $ELF | grep '^sha1:' | awk '{print $2}')
[ "$SYS_SHA1" = "$OUR_SHA1" ] && ok "hash sha1 matches sha1sum" || bad "hash sha1 ($OUR_SHA1 vs $SYS_SHA1)"
# strings --utf16: PE-фикстура с UTF-16 строкой
python3 - << 'PYEOF'
import struct
# tiny ELF64 c UTF-16LE строками в .text
utf16 = 'Hello World'.encode('utf-16-le') + b'\x00\x00' + 'Error message here'.encode('utf-16-le') + b'\x00\x00'
buf = bytearray(64)
buf[0:4] = b'\x7fELF'
buf[4] = 2; buf[5] = 1; buf[6] = 1
buf[16:18] = struct.pack('<H', 2)
buf[18:20] = struct.pack('<H', 62)
buf[20:24] = struct.pack('<I', 1)
buf[24:32] = struct.pack('<Q', 0x1000)
buf[52:54] = struct.pack('<H', 64)
buf[58:60] = struct.pack('<H', 64)
data_off = 0x100
shstr = b'\0.text\0.shstrtab\0'
shoff = (data_off + len(utf16) + len(shstr) + 7) & ~7
buf += b'\x00' * (data_off - 64)
buf += utf16
buf += shstr
buf += b'\x00' * (shoff - len(buf))
buf[40:48] = struct.pack('<Q', shoff)
buf[60:62] = struct.pack('<H', 3)
buf[62:64] = struct.pack('<H', 2)
text_sh = struct.pack('<IIQQQQIIQQ', 1, 1, 6, 0x1000, data_off, len(utf16), 0, 0, 1, 0)
str_sh = struct.pack('<IIQQQQIIQQ', 7, 3, 0, 0, data_off + len(utf16), len(shstr), 0, 0, 1, 0)
buf += b'\x00' * 64 + text_sh + str_sh
open('/tmp/ba_utf16.elf','wb').write(buf)
PYEOF
$BA strings /tmp/ba_utf16.elf --utf16 --min-len 4 2>/dev/null | grep -q "Hello World" && ok "strings utf16" || bad "strings utf16"
$BA strings /tmp/ba_utf16.elf --utf16 --limit 1 --json 2>/dev/null | grep -q '"total": 2' && ok "strings limit json" || bad "strings limit"
# entropy --window
$BA entropy $ELF +0 --len 8192 --window 1024 2>/dev/null | grep -q "windows" && ok "entropy window profile" || bad "entropy window"
$BA --json entropy $ELF +0 --len 8192 --window 1024 2>/dev/null | grep -q '"profile"' && ok "entropy window json" || bad "entropy window json"
# disasm --until-ret: заканчивается на ret
$BA disasm $ELF 0x2476 --until-ret 2>/dev/null | tail -1 | grep -q "ret" && ok "disasm until-ret ends at ret" || bad "disasm until-ret"
# symbols --limit
$BA symbols $ELF --limit 5 --json 2>/dev/null | grep -q '"shown": 5' && ok "symbols limit" || bad "symbols limit"
# run: timed_out флаг
$BA run /bin/sleep --timeout-secs 1 -- 5 2>/dev/null | grep -q "TIMED OUT" && ok "run timed_out flag" || bad "run timed_out"
$BA --json run /bin/sleep --timeout-secs 1 -- 5 2>/dev/null | grep -q '"timed_out": true' && ok "run timed_out json" || bad "run timed_out json"
# record: timed_out в снимке
$BA record /bin/sleep --snapshot /tmp/ba_snap_to.json --timeout-secs 1 -- 5 >/dev/null 2>&1
grep -q '"timed_out": true' /tmp/ba_snap_to.json && ok "record timed_out in snapshot" || bad "record timed_out"
# carve: новые магики
python3 -c "open('/tmp/ba_carve3.bin','wb').write(b'xxRar!\x1a\x07\x00yy7z\xbc\xaf\x27\x1czzMSCFww\xfd7zXZ\x00vv\x28\xb5\x2f\xfduu\xd0\xcf\x11\xe0ttUPX!')"
for M in RAR 7z CAB xz zstd OLE2 UPX; do
  $BA carve /tmp/ba_carve3.bin --json 2>/dev/null | grep -q "\"$M\"" && ok "carve $M" || bad "carve $M"
done

# --- operand-level conformance metric (lesson from D1: length-only checks
# --- miss register-name errors; this compares mnemonic+operands vs objdump)
METRIC="$SCRIPT_DIR/operand_metric.py"
# ELF: /bin/true .text (x64)
python3 "$METRIC" /bin/true .text +0x1000 0x2b50 95 50 "operand metric ELF x64" "$BA" && ok "operand metric ELF" || bad "operand metric ELF"
# PE: сгенерированная фикстура
python3 "$METRIC" "$PE" .text +0x400 64 95 50 "operand metric PE fixture" "$BA" && ok "operand metric PE" || bad "operand metric PE"
# большой реальный PE, если задан (AutoChart.exe: i386, ~1M инструкций)
# AC=<путь> экспортом; по умолчанию — upload/AutoChart.exe, если существует
if [ -z "$AC" ]; then
  for _cand in /home/z/my-project/upload/AutoChart.exe; do
    [ -f "$_cand" ] && AC="$_cand"
  done
fi
if [ -n "$AC" ] && [ -f "$AC" ]; then
  python3 "$METRIC" "$AC" .text +0x400 0x2fe000 95 70 "operand metric AutoChart i386" "$BA" && ok "operand metric AutoChart" || bad "operand metric AutoChart"
else
  skip "operand metric AutoChart (нет AC=${AC:-unset})"
fi

# resources: PE-дерево ресурсов
if [ -n "$AC" ] && [ -f "$AC" ]; then
  $BA resources $AC 2>/dev/null | head -1 | grep -q "1791 entries" && ok "resources AutoChart tree" || bad "resources AutoChart"
  $BA --json resources $AC 2>/dev/null | grep -q '"type_name": "VERSION"' && ok "resources json VERSION" || bad "resources json"
  # RT_VERSION лист = тот же rva, что парсер VersionInfo в inspect
  $BA --json resources $AC 2>/dev/null | grep -q '"rva": 7292008' && ok "resources version leaf rva" || bad "resources leaf rva"
else
  skip "resources AutoChart (нет AC)"
fi
check "resources non-PE -> rc2" 2 $BA resources /bin/true
# functions: прологи + символы
$BA functions /bin/true --limit 5 2>/dev/null | head -1 | grep -q "functions: 86" && ok "functions /bin/true count" || bad "functions count"
$BA --json functions /bin/true 2>/dev/null | grep -q '"symbol": "error"' && ok "functions json symbol" || bad "functions json symbol"
$BA functions /bin/true 0x1000 --limit 3 >/dev/null 2>&1 && bad "functions extra arg" || ok "functions no extra args"
if [ -n "$AC" ] && [ -f "$AC" ]; then
  $BA functions $AC --limit 3 2>/dev/null | grep -q "prologue-ebp" && ok "functions AutoChart prologues" || bad "functions AutoChart"
else
  skip "functions AutoChart (нет AC)"
fi
check "functions non-x86 -> rc2" 2 $BA functions /etc/hostname
# .NET (COR20) заголовки
python3 "$SCRIPT_DIR/make_dotnet_fixture.py" /tmp/ba_dotnet.exe >/dev/null 2>&1 || python3 "$(dirname "$0")/make_dotnet_fixture.py" /tmp/ba_dotnet.exe >/dev/null
$BA --json inspect /tmp/ba_dotnet.exe 2>/dev/null | grep -q '"runtime_version": "v2.0.50727"' && ok "dotnet runtime version" || bad "dotnet runtime version"
$BA --json inspect /tmp/ba_dotnet.exe 2>/dev/null | grep -q '"flags": "ILONLY"' && ok "dotnet ILONLY flag" || bad "dotnet flags"
$BA --json inspect /tmp/ba_dotnet.exe 2>/dev/null | grep -q '"entry_point_token": "0x06000001"' && ok "dotnet entry token" || bad "dotnet entry token"
# у нативного PE поля dotnet нет
$BA --json inspect "$PE" 2>/dev/null | grep -q '"dotnet"' && bad "dotnet absent for native PE" || ok "dotnet absent for native PE"

echo "== MCP v0.2 =="
# 20 инструментов в tools/list
NTOOLS=$($BA mcp << 'MCPEOF' | python3 -c "import json,sys; print(len(json.load(sys.stdin)['result']['tools']))"
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
MCPEOF
)
[ "$NTOOLS" = "21" ] && ok "mcp 21 tools" || bad "mcp tools count ($NTOOLS)"
# search через MCP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"path":"/bin/true","pattern":"GLIBC"}}}' | $BA mcp | grep -q '\\"matches\\"' && ok "mcp search tool" || bad "mcp search"
# xrefs через MCP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"xrefs","arguments":{"path":"/bin/true","target":"error"}}}' | $BA mcp | grep -q 'xrefs_total' && ok "mcp xrefs tool" || bad "mcp xrefs"
# disasm until_ret через MCP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"disasm","arguments":{"path":"/bin/true","start":"0x2476","until_ret":true}}}' | $BA mcp | python3 -c "import json,sys; r=json.load(sys.stdin); d=json.loads(r['result']['content'][0]['text']); sys.exit(0 if d['insns'][-1]['mnemonic']=='ret' else 1)" && ok "mcp disasm until_ret" || bad "mcp disasm until_ret"
# strings utf16 через MCP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"strings","arguments":{"path":"/tmp/ba_utf16.elf","utf16":true,"min_len":4}}}' | $BA mcp | grep -q 'Hello World' && ok "mcp strings utf16" || bad "mcp strings utf16"
# entropy window через MCP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"entropy","arguments":{"path":"/bin/true","start":"+0","len":8192,"window":1024}}}' | $BA mcp | grep -q 'profile' && ok "mcp entropy window" || bad "mcp entropy window"
# symbols limit через MCP
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"symbols","arguments":{"path":"/bin/true","limit":5}}}' | $BA mcp | python3 -c "import json,sys; r=json.load(sys.stdin); d=json.loads(r['result']['content'][0]['text']); sys.exit(0 if d['shown']==5 and d['total']>5 else 1)" && ok "mcp symbols limit" || bad "mcp symbols limit"

echo "== MCP =="
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | $BA mcp | grep -q '"protocolVersion"' && ok "mcp initialize" || bad "mcp initialize"
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | $BA mcp | grep -q '"inspect"' && ok "mcp tools/list" || bad "mcp tools/list"
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect","arguments":{"path":"/bin/true"}}}' | $BA mcp | grep -q 'file_size' && ok "mcp tools/call inspect" || bad "mcp tools/call inspect"
echo '{"jsonrpc":"2.0","id":4,"method":"ping"}' | $BA mcp | grep -q '"result":{}' && ok "mcp ping" || bad "mcp ping"
# notifications (no id) must NOT produce any response line
N=$(printf '{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":9,"method":"ping"}\n' | $BA mcp | wc -l)
[ "$N" -eq 1 ] && ok "mcp notification silent" || bad "mcp notification silent ($N lines)"
# unknown method -> top-level error object with code -32601
echo '{"jsonrpc":"2.0","id":5,"method":"bogus/method"}' | $BA mcp | grep -q '"error".*-32601' && ok "mcp unknown method error" || bad "mcp unknown method"
# strict argument types: number where string expected
echo '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"inspect","arguments":{"path":123}}}' | $BA mcp | grep -qi "must be a string" && ok "mcp strict types" || bad "mcp strict types"
# carve: BSS (SHT_NOBITS) не расширяет размер встроенного ELF
python3 -c "
elf = open('/bin/true','rb').read()
open('/tmp/ba_carve2.bin','wb').write(b'GARBAGE'*10 + elf + b'TAIL'*100)"
$BA carve /tmp/ba_carve2.bin --json 2>/dev/null | grep -q 'non-NOBITS' && ok "carve ELF skips BSS" || bad "carve BSS"
check "mcp-setup" 0 $BA mcp-setup --app generic
check "mcp-setup claude" 0 $BA mcp-setup --app claude

# ===== 0.2.1: аудитные регрессионные тесты =====
echo "== 0.2.1 audit fixes =="

# 1) run не зависает на демонирующейся цели и не оставляет процессов
cat > /tmp/ba_daemon.sh << 'EOS'
#!/bin/bash
setsid bash -c 'sleep 300' &
echo parent-done
exit 0
EOS
chmod +x /tmp/ba_daemon.sh
pkill -f "sleep 300" 2>/dev/null; sleep 0.2
if timeout 20 "$BA" run --timeout-secs 2 /tmp/ba_daemon.sh > /tmp/ba_daemon_out.txt 2>&1; then
  sleep 0.5
  if pgrep -f "sleep 300" > /dev/null; then bad "run daemon: leaked grandchild"
  else ok "run daemon: returns, no leak"
  fi
else
  bad "run daemon: run hung or failed (rc=$?)"
fi
pkill -f "sleep 300" 2>/dev/null

# 2) run убивает долгую цель по таймауту
if timeout 20 "$BA" run --timeout-secs 2 /bin/sleep 60 2>&1 | grep -q "TIMED OUT"; then
  ok "run timeout kill"
else
  bad "run timeout kill"
fi

# 3) disasm resync: строка с 0x62 внутри кода не останавливает проход
python3 - << 'PYFIX'
import struct
payload = b"\x48\x89\xc3" + b"blk transfo" + b"\x48\x31\xc0" + b"\xc3"
buf = bytearray(64)
buf[0:4]=b'\x7fELF'; buf[4]=2; buf[5]=1; buf[6]=1
buf[16:18]=struct.pack('<H',2); buf[18:20]=struct.pack('<H',62)
buf[20:24]=struct.pack('<I',1); buf[24:32]=struct.pack('<Q',0x1000)
buf[52:54]=struct.pack('<H',64); buf[58:60]=struct.pack('<H',64)
data_off=0x100
buf += b'\x00'*(data_off-64)+payload
shstr_off = len(buf)
buf += b'\0.text\0.shstrtab\0'
while len(buf) % 8: buf.append(0)
shoff = len(buf)
buf[40:48]=struct.pack('<Q',shoff); buf[60:62]=struct.pack('<H',3); buf[62:64]=struct.pack('<H',2)
text=struct.pack('<IIQQQQIIQQ',1,1,6,0x1000,data_off,len(payload),0,0,1,0)
sh=struct.pack('<IIQQQQIIQQ',7,3,0,0,shstr_off,16,0,0,1,0)
buf += b'\x00'*64+text+sh
open('/tmp/ba_resync.elf','wb').write(bytes(buf))
PYFIX
N=$("$BA" --json disasm /tmp/ba_resync.elf +0x100 --len 64 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['insns']))")
[ "$N" -gt 5 ] && ok "disasm resync past data island ($N insns)" || bad "disasm resync ($N insns)"

# 4) xrefs JSON содержит unscanned_bytes
"$BA" --json xrefs /bin/true error 2>/dev/null | grep -q '"unscanned_bytes"' && ok "xrefs coverage field" || bad "xrefs coverage field"

# 5) UTF-16 кириллица извлекается
python3 - << 'PYFIX2'
import struct
payload = "Привет мир".encode("utf-16-le") + b"\x00\x00"
buf = bytearray(64)
buf[0:4]=b'\x7fELF'; buf[4]=2; buf[5]=1; buf[6]=1
buf[16:18]=struct.pack('<H',2); buf[18:20]=struct.pack('<H',62)
buf[20:24]=struct.pack('<I',1); buf[24:32]=struct.pack('<Q',0x1000)
buf[52:54]=struct.pack('<H',64); buf[58:60]=struct.pack('<H',64)
data_off=0x100
buf += b'\x00'*(data_off-64)+payload
shstr_off = len(buf)
buf += b'\0.text\0.shstrtab\0'
while len(buf) % 8: buf.append(0)
shoff = len(buf)
buf[40:48]=struct.pack('<Q',shoff); buf[60:62]=struct.pack('<H',3); buf[62:64]=struct.pack('<H',2)
text=struct.pack('<IIQQQQIIQQ',1,1,6,0x1000,data_off,len(payload),0,0,1,0)
sh=struct.pack('<IIQQQQIIQQ',7,3,0,0,shstr_off,16,0,0,1,0)
buf += b'\x00'*64+text+sh
open('/tmp/ba_cyr.elf','wb').write(bytes(buf))
PYFIX2
"$BA" strings /tmp/ba_cyr.elf --utf16 --min-len 2 | grep -q "Привет" && ok "strings utf16 cyrillic" || bad "strings utf16 cyrillic"

# 6) until-ret не выходит за границу секции
python3 - << 'PYFIX3'
import struct
payload = b"\x90"*64  # nops, no ret
buf = bytearray(64)
buf[0:4]=b'\x7fELF'; buf[4]=2; buf[5]=1; buf[6]=1
buf[16:18]=struct.pack('<H',2); buf[18:20]=struct.pack('<H',62)
buf[20:24]=struct.pack('<I',1); buf[24:32]=struct.pack('<Q',0x1000)
buf[52:54]=struct.pack('<H',64); buf[58:60]=struct.pack('<H',64)
data_off=0x100
buf += b'\x00'*(data_off-64)+payload
shstr_off = len(buf)
buf += b'\0.text\0.shstrtab\0'
while len(buf) % 8: buf.append(0)
shoff = len(buf)
buf[40:48]=struct.pack('<Q',shoff); buf[60:62]=struct.pack('<H',3); buf[62:64]=struct.pack('<H',2)
text=struct.pack('<IIQQQQIIQQ',1,1,6,0x1000,data_off,len(payload),0,0,1,0)
sh=struct.pack('<IIQQQQIIQQ',7,3,0,0,shstr_off,16,0,0,1,0)
buf += b'\x00'*64+text+sh
open('/tmp/ba_noret.elf','wb').write(bytes(buf))
PYFIX3
"$BA" disasm /tmp/ba_noret.elf 0x1000 --until-ret 2>/dev/null | grep -q "add .rax., eax" && bad "until-ret section clamp" || ok "until-ret section clamp"

# 7) --until-ret + --count отвергаются
"$BA" disasm /tmp/ba_noret.elf 0x1000 --until-ret --count 5 >/dev/null 2>&1 && bad "until-ret count conflict" || ok "until-ret count conflict"

# 8) hash: md5/sha1/sha256 соответствуют системным утилитам на /bin/true
SYS_MD5=$(md5sum /bin/true | cut -d' ' -f1)
SYS_SHA1=$(sha1sum /bin/true | cut -d' ' -f1)
SYS_SHA256=$(sha256sum /bin/true | cut -d' ' -f1)
OURS=$("$BA" hash /bin/true)
echo "$OURS" | grep -q "$SYS_MD5" && ok "hash md5 = md5sum" || bad "hash md5"
echo "$OURS" | grep -q "$SYS_SHA1" && ok "hash sha1 = sha1sum" || bad "hash sha1"
echo "$OURS" | grep -q "$SYS_SHA256" && ok "hash sha256 = sha256sum" || bad "hash sha256"

echo
TOTAL=$((PASS+FAIL+SKIP))
if [ "$SKIP" -gt 0 ]; then
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP (executed $((PASS+FAIL)) of $TOTAL; skipped need AC=<path>)"
else
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP (executed $((PASS+FAIL)) of $TOTAL)"
fi
[ $FAIL -eq 0 ] && echo "ALL OK" || exit 1
