# bin-anything

![CI](https://github.com/casper05/BinToRust/actions/workflows/ci.yml/badge.svg)


**Swiss-army CLI + MCP-сервер для ИИ-агентов, работающих с готовыми бинарниками (ELF/PE).**

Вдохновлено [rust-anything](https://github.com/erkamyaman/rust-anything): тот инструмент
помогает агенту переписывать *исходный код* на Rust с проверкой поведения на каждом шаге.
`bin-anything` применяет ту же философию «инструмент-как-помощник-агента» к **скомпилированным
бинарникам**, когда исходников нет: реверс-инжиниринг, анализ, сравнение версий, патчинг,
проверка поведения.

## Ключевые свойства

- **Чистый Rust, нулевые системные зависимости.** Парсеры ELF/PE, SHA-256, x86/x64-дизасемблер
  написаны с нуля — один статический бинарь работает на любом Linux без binutils/objdump.
- **Два интерфейса для агента**: обычный CLI (JSON-вывод `--json`) и MCP-сервер (stdio
  JSON-RPC 2.0) для Claude Code, Cursor и любых MCP-хостов.
- **Проверяемое поведение**: `record` фиксирует снимок поведения (exit code, хэши stdout/stderr,
  созданные файлы), `replay` повторяет прогон и показывает, что изменилось — как
  record→diff в rust-anything, но для готовых бинарников.
- **Дизасм проверен против objdump**: на `/bin/true`, `/bin/ls`, `/usr/bin/gcc`, mingw-PE,
  а также на всей `.text` libcrypto (3.6 МБ, ~860k инструкций, включая 28k AVX/AVX-512) и
  libgfortran: 95–96% начал инструкций совпадают с objdump, остаток — «островки данных»
  внутри кода, где линейный проход и objdump расходятся в разбиении (у них нет единственно
  верного ответа). Декодер не останавливается на данных: сбойный байт выдаётся как `db` и
  проход продолжается (resync), поле `stopped` в JSON отражает число resync-ов.

## Поддерживаемые форматы

| Формат | разрядность | секции | символы | импорты | экспорты | дизасм |
|---|---|---|---|---|---|---|
| ELF | 32/64 LE | ✓ | symtab + dynsym | undefined dynsym | defined dynsym | x86, x64 |
| PE (EXE/DLL) | 32/64 | ✓ | экспорты | import table (IAT) | export directory | x86, x64 |

Mach-O не поддерживается (добавляется при необходимости).

## Команды

### Анализ

```text
bin-anything inspect <bin>                  # формат, arch, entry, счётчики, митигации, packed-эвристика
bin-anything sections <bin>                 # секции: vaddr/offset/размеры/флаги/энтропия
bin-anything symbols <bin> [--filter F] [--kind func|object|...] [--limit N]
bin-anything imports <bin>                  # ELF: undefined dynsym; PE: import table с модулями
bin-anything exports <bin>
bin-anything strings <bin> [--min-len N] [--filter F] [--limit N] [--utf16]
bin-anything search <bin> '<pattern>' [--max N]
                                             # байтовый поиск с wildcard: '\xe8????????' или ASCII
bin-anything functions <bin> [--limit N]    # границы функций: прологи (push rbp/mov rbp,rsp, endbr64) + символы
bin-anything resources <bin>                # PE: дерево ресурсов .rsrc (типы RT_*, имена, языки, офсеты)
bin-anything xrefs <bin> <target>           # ссылки на адрес/символ: call/jmp/jcc + RIP-relative data
bin-anything hex <bin> <start> [--len N]    # start: 0xADDR | +OFFSET | имя символа
bin-anything disasm <bin> <start> [--count N] [--len N] [--until-ret]
bin-anything hash <bin>                     # MD5, SHA-1, SHA-256, CRC32, FNV-1a64
bin-anything entropy <bin> <start> [--len N] [--window N]  # Шеннон-энтропия / профиль по окнам
```

Пример: адресация единобразна — виртуальный адрес (`0x401000`), файловый офсет (`+0x400`)
или имя символа (`main`). Для PE виртуальные адреса включают image base
(`0x140001000`), у ELF — как в `readelf`.

`search` ищет паттерн по всему файлу: `\xNN`-эскейпы, ASCII-символы, `??`/`..` —
любой байт. Примеры: `\xe8????????` — все `call rel32`; `\x48\x89????\x48` —
`mov` с REX.W; `CC Strat` — ASCII-подстрока.

`xrefs` сканирует все code-секции и находит прямые `call`/`jmp`/`jcc` на цель и
RIP-relative обращения к данным (структурированное поле `rip_target` в JSON
дизасма). Сверено с objdump: `/bin/true` (3 call на `error`) и libcrypto
(16/16 вызовов PLT-стаба `ERR_clear_error`). Поле `unscanned_bytes` в JSON
показывает, сколько байт не просканировано (обычно 0).

### Сравнение и изменение

```text
bin-anything compare <a> <b> [--max-chunks N]  # байтовый дифф: регионы + hex-чанки + sha256
bin-anything patch <bin> <at> <bytes> [--output F] [--backup]
                                             # at: 0xADDR | +OFFSET | символ; bytes: '\x90\x90' или ASCII
bin-anything carve <bin> [--min-size N]     # поиск встроенных PE/ELF/gzip/ZIP/PNG/JPEG/RAR/7z/CAB/xz/zstd/OLE2/UPX
bin-anything extract <bin> <offset> <size> <output>
```

`patch` не меняет исходный файл, если задан `--output`; с `--backup` создаёт `<input>.bak`.

### Поведение (record → replay)

```text
bin-anything run <bin> [args...] [--timeout-secs N] [--env K=V] [--cwd DIR]
bin-anything record <bin> --snapshot snap.json [--stdin-file F] [--watch-dir D]
                     [--env K=V] [--cwd DIR] [--timeout-secs N] [-- args...]
bin-anything replay snap.json [--timeout-secs N]
```

Типичный сценарий ИИ-агента (проверить, что патч не сломал поведение):

```bash
bin-anything record ./app --snapshot before.json -- input.dat
bin-anything patch ./app +0x4012 '\x90' --output ./app.patched
# поменять argv в снимке или патчнуть копию:
bin-anything record ./app.patched --snapshot after.json -- input.dat
bin-anything replay after.json   # либо сравнить before.json/after.json вручную
```

`replay` сверяет: exit code, сигнал, sha256 stdout/stderr, созданные/изменённые файлы
в `--watch-dir`. Снимок самодостаточен: переменные окружения (`--env`), stdin из
`--stdin-file` (до 64 КиБ встраивается в JSON) и использованный таймаут сохраняются
и автоматически воспроизводятся при `replay` — повторный прогон детерминирован без
ручного повторения флагов. `--timeout-secs` у `replay` переопределяет записанный.

### MCP-сервер

```text
bin-anything mcp            # stdio JSON-RPC 2.0 (протокол MCP 2025-06-18)
bin-anything mcp-setup --app claude|cursor|generic   # готовые конфиги
```

21 инструмент (`inspect`, `sections`, `symbols`, `imports`, `exports`, `functions`,
`resources`, `strings`, `hex`,
`disasm`, `hash`, `entropy`, `search`, `xrefs`, `compare`, `patch`, `carve`, `extract`,
`run`, `record`, `replay`) — по одному на каждую CLI-команду, аргументы идентичны
(например, `disasm` принимает `until_ret`, `strings` — `utf16`/`limit`).

Подключение к Claude Code:

```bash
claude mcp add bin-anything -- /path/to/bin-anything mcp
```

Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "bin-anything": { "command": "/path/to/bin-anything", "args": ["mcp"] }
  }
}
```

## Сборка

```bash
cargo build --release    # Rust 1.75+, никаких системных зависимостей
```

Разработка: `cargo test` (39 тестов, включая регрессионные на VEX/EVEX/XOP, fwait-склейку,
shrd cl-форму, пределы окна дизасма, i386-специфику — in/out imm8, retf, salc, arpl,
lds/les, moffs с 66-префиксом, fstsw — и новые v0.2-функции: search с wildcard, xrefs на
call/jmp/RIP-data, UTF-16 strings, until-ret, MD5/SHA-1 векторы, entropy-профиль,
carve-магики); сквозные проверки — `scripts/e2e_test.sh` (119, включая сверку xrefs с
objdump, MD5/SHA-1 с md5sum/sha1sum и метрику конформности операндов
`operand_metric.py`: доля совпадающих мнемоника+операнды против objdump
на /bin/true, PE-фикстуре и AutoChart.exe — порог 95%/50–70%) и `scripts/verify_disasm.py` (сверка дизасма с
objdump на `/bin/true`, `/bin/ls`, `/usr/bin/gcc`). Релизная дисциплина: полный гейт + проверка `--version` артефакта против
Cargo.toml до обновления поставки.
CI (`.github/workflows/ci.yml`): build, unit, гейт покрытия опкодов
(`opcode_coverage.py --threshold 100`), fmt, e2e, verify_disasm, R2-корпус
(`corpus_r2.py`) и оба audit-скрипта. В JSON дизасма каждая инструкция несёт
`confidence` (high = конкретная мнемоника из таблиц; medium = family-скетч;
low = `db`/плейсхолдер `op_0f_xx` — длина верна, имя приближённое), плюс
сводка `confidence_summary`. Лицензия — MIT (см. `LICENSE`).

## История версий

- **0.2.4** — издание 3 (R4+R2+R5): декодер — замер покрытия опкодов стал
  гейтом (`opcode_coverage.py`: синтетический корпус всех 256 одно-байтовых
  опкодов + батарея редких семейств, сверка длин и мнемоник с capstone;
  100%/100% по длинам, 0 паник); исправлены паники на ENTER (imm16+imm8) и
  CALLF/JMPF (far ptr), x87 reg-form таблица приведена к Intel SDM (FCMOV/
  FFREE/FUCOM/FFREEP/FUCOMI-строки, реверс FSUB/FSUBR и FDIV/FDIVR в DC/DE),
  конкретные имена вместо скетчей для SSE/SSSE3/SSE4 (pmovmskb, pshufb,
  palignr, psubb/paddb-семейство, pandn/por/pxor, prefetcht0..t2,
  movdqa/movdqu/vmovdqa/vmovdqu, vpcmpeqb/w/d, vpmin/vpmax, kmovw/b/d/q,
  tzcnt/lzcnt, movabs, psrldq/pslldq), суффиксы строковых операций
  (movsd vs movsq по REX.W), rep/repne-склейка stos/lods/scas, режимозависимые
  pushfd/pushfq, iretd, cwde/cdqe, loopne/loope/jecxz/jrcxz, clc..std;
  `endbr64`/prefetch без мусорных операндов; `jmp/call r/m` печатает
  64-битные регистры в x64; R2-корпус (`corpus_r2.py`: gcc -O0/-O2/-Os/
  -static/-PIE, PE64, .NET — 9 PASS/0 FAIL/2 SKIP с честным SKIP-
  логированием; static-билд 89→96% мнемоник); R5 — уровни доверия в JSON
  дизасма: поле `confidence` per-insn (high/medium/low) и сводка
  `confidence_summary` (high/medium/low counts), чтобы агент мог отличать
  конкретные имена от family-скетчей и `db`-байтов; e2e 119/119, юнит-тесты
  48, verify_disasm 3/3 (133k инструкций), rustfmt-чисто.
- **0.2.3** — дорожная карта после полевого теста AutoChart.exe: `functions` (границы
  функций по прологам push rbp/mov rbp,rsp и endbr64, склейка с символами);
  `resources` (дерево PE-ресурсов: RT_-типы, имена UTF-16, языки, data-листья);
  .NET (COR20) заголовки в `inspect` (runtime version, флаги ILONLY/32BITREQUIRED,
  metadata RVA, entry point token); аннотация `call [IAT]` именем импорта прямо в
  дизасме (`call [0x6ff0a8] <CRYPT32.dll!CryptDecodeObjectEx>`); сегментные
  префиксы (`mov rsi, fs:[0x28]`), hex-смещения RIP; e2e-метрика уровня операндов
  (119 тестов, пороги мнемоник 95% и полных пар 50–70%); MCP: 21 инструмент.
  Пост-релизная стабилизация (по итогам повторного верификационного прогона):
  декодер i386 — in/out с imm8-портом (E4–E7), retf (CA/CB), salc (D6), arpl (63),
  lds/les (C4/C5 вне 64-бит), int1 (F1), moffs16:32 (`66 a3` — регистр сужается,
  адрес остаётся 32-битным), двойная fwait-склейка `9b 9b df e0` → `fstsw` —
  все 44 расхождения длин с objdump на AutoChart устранены до нуля (юнит-тесты
  `decoder_i386_*`, helper `tiny_elf32`); Cargo-версия поднята до 0.2.3 (раньше
  исходники 0.2.3 носили версию 0.2.1, а поставляемый бинарник был 0.2.0 —
  закрыт класс «поставка не верифицирована как артефакт»: релизный скрипт
  проверяет `--version` артефакта перед обновлением download/).
- **0.2.2** — исправление всех 12 дефектов полевого теста AutoChart.exe: i386-регистры
  (мнемоники 85.5→98.4%, полные пары 21.5→75%), абсолютные [disp32] цели в xrefs
  (9 080 невидимых вызовов IAT), UTF-16 фильтр когерентности (шум 72.8→10.9%),
  конкретные мнемоники Jcc/Setcc/Cmovcc/FPU/lock/movs/cdq, ординальные импорты
  ws2_32/oleaut32, VS_VERSIONINFO, честная диагностика run, entropy --len 0.
- **0.2.0** — `search` (байтовые паттерны с wildcard), `xrefs` (call/jmp/jcc + RIP-relative
  data), `strings --utf16/--limit`, `symbols --limit`, `entropy --window` (профиль),
  `disasm --until-ret`, `hash` +MD5/SHA-1, `carve` +RAR/7z/CAB/xz/zstd/OLE2/UPX,
  `run/record/replay`: флаг `timed_out` и капча вывода 16 МиБ, MCP: 19 инструментов.
  Структурированное поле `rip_target` в JSON дизасма.
- **0.2.1** — аудитный релиз: `run` больше не зависает на демонирующихся целях и не
  оставляет процессов (process group + subreaper + orphan sweep); дизасм resync вместо
  останова на данных (libcrypto .text: 68% → 95% покрытия objdump); `xrefs` честно
  сообщает `unscanned_bytes`; `compare`/`hash` не клонируют вход (2×100 МБ → 203 МБ RSS
  вместо 303); UTF-16 strings извлекают кириллицу/CJK; `--until-ret` не выходит за
  границу секции; clippy 0 предупреждений, cargo fmt чисто.
- **0.1.0** — первый релиз: ELF/PE парсеры, дизасм x86/x64 с AVX/AVX-512, patch/carve,
  record→replay, MCP-сервер.

## Ограничения

- Дизасм: x86/x64 только, включая векторные префиксы VEX (AVX/AVX2), EVEX (AVX-512) и
  XOP (AMD): длины и ModRM/SIB/disp разбираются корректно, мнемоники покрывают
  распространённые векторные опкоды (редкие показываются как `vex_0f38`-стиль с верной
  длиной). Скалярные редкие опкоды — `op_0f_xx` (длины корректны). Не эмулирует исполнение —
  это статический линейный проход; в «островках данных» внутри .text разбиение на
  инструкции может отличаться от objdump (у линейного прохода нет единственно верного
  ответа на данных).
- `run/record/replay` выполняют бинарник **как есть** (без песочницы): применяйте к доверенным
  или изолированным файлам.
- Отладочные форматы (DWARF/PDB) не парсятся; символы берутся из таблиц ELF и export-таблиц PE.
- 32-битный дизасм протестирован слабее 64-битного.

## Лицензия

MIT
