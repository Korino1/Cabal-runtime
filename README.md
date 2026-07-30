# Cabal Runtime

Cabal Runtime moves deterministic, context-heavy repository mechanics behind
standard Codex CLI hooks. The model keeps using ordinary commands. For exact
supported forms, the plugin executes or projects the operation natively and
returns a bounded semantic result instead of raw logs, patch bodies, repeated
file contents, repository bookkeeping, or an unnecessarily large file list.

No Codex fork is used. The model does not call a Cabal MCP tool, load a Cabal
skill, or perform an extra workflow step.

## How Context Noise Is Removed

The installed plugin uses standard `PreToolUse`, `PostToolUse`, `SessionStart`,
`PostCompact`, and `Stop` hooks.

1. Codex requests an ordinary supported command.
2. `PreToolUse` recognizes only a frozen exact grammar and uses
   `updatedInput` to route it to `cabal-runtime-hook`.
3. The Rust runtime keeps raw data and private indexes outside model context.
4. The command result contains only bounded decision-relevant fields, explicit
   omissions, and completeness status.
5. Unsupported commands receive no Cabal rewrite and retain normal Codex
   behavior.

This is transparent for the supported hook paths, not universal interception.
Cabal does not claim control over unsupported tools, arbitrary shell syntax,
all `unified_exec` paths, or MCP-side mutations.

Outputs from MemoryX, Safeguard, other MCP servers, Codex apps, and third-party
plugins remain owned by those providers. Cabal does not shorten, replace,
suppress, or store their returned content. Context reduction applies only to
the exact Cabal-owned command forms documented below.

## Implemented Modules

### Cargo Gateway

Simple `cargo build`, `cargo check`, `cargo clippy`, and `cargo test` commands
run through the native gateway. Full compiler and test streams stay in local
ignored artifacts. The model receives verdicts, error codes, actionable
diagnostics, source locations, and test summaries without build progress noise.

### Artifact and Log Gateway

Exact simple reads of `*.junit.xml`, `*.sarif`, `*.sarif.json`,
`*.nextest.log`, and `*.log`, plus simple `cargo nextest run` commands, are
normalized. JUnit captured output, repetitive lines, and raw report structure
stay local. Malformed structured reports never become a false success.

### Git Delta Gateway

Exactly `git status`, `git diff`, `git diff --cached`, and a bounded
`git show <revision>` are projected into changed paths, statuses,
classifications, counts, and hunk ranges. Patch bodies remain under the Git
service directory. Flags, pathspecs, revision ranges, redirection, and composed
shell commands are left unchanged.

### File Read Delta Cache

Exact bounded UTF-8 reads through `cat`, `Get-Content`, and a narrow `sed -n`
form are versioned by content hash. A repeated covered read of unchanged bytes
returns a small `unchanged` receipt. A changed file returns current requested
content plus bounded changed-line ranges. Binary, oversized, out-of-workspace,
or unsupported reads remain under normal Codex execution.

### Completion Gate

The opt-in `.cabal/completion/contract.json` is checked by the standard `Stop`
hook. An absent contract is silent. A satisfied contract adds no continuation.
Missing, stale, failed, malformed, or unavailable evidence produces one bounded
continuation containing safe criterion IDs or a generic status. Supported
criteria include Cargo command receipts, file existence/absence, and exact file
SHA-256.

### Change Policy Guard

The opt-in `.cabal/policy/change_policy.json` checks canonical `apply_patch`
and bounded simple Bash mutations before execution. It covers declared path
classes, workspace and existing-symlink containment, patch limits, exact
command rules, and built-in destructive forms. Allow is silent. Deny uses the
native `permissionDecision: "deny"` wire with one bounded code. Unsupported
grammar receives no policy decision.

### Repository Map

M-009 maintains `cabal.repository_map.v1` privately under the repository Git
service directory. It records:

- normalized file facts, SHA-256 versions, classifications, and explicit parse
  status;
- Cargo workspace packages, targets, and direct package dependency edges from
  `cargo metadata`;
- Rust modules, definitions, public/restricted visibility, imports, syntactic
  references, qualified impl/trait methods, tests, and test-to-symbol
  references from the `syn` AST;
- hard omission counters and complete/bounded/Cargo-unavailable state.

The index is refreshed silently on `SessionStart`, after supported edit tools,
and before a broad inventory rewrite when the current map predicts a smaller
projection. Unchanged files reuse parsed
facts; changed, added, and deleted files invalidate the corresponding facts.
The runtime excludes `.git`, does not follow symlinks, rejects state outside the
Git service directory, and atomically persists a deterministic bounded index.

For exactly `rg --files` and `rg --files .`, `PreToolUse` may return a bounded
`cabal.repository_inventory.v1` instead of the full list. The rewrite occurs
only when the projection is smaller than the estimated native result. Small
repositories therefore pass through unchanged rather than receiving more
context. Unsupported arguments, hidden-file flags, pipes, redirects, and
compound commands are never rewritten by this module.

In a local 2,003-file fixture, the native file list was 118,038 UTF-8 bytes and
the bounded inventory was 15,990 bytes, an 86.45% reduction. This fixture is a
regression measurement, not a universal performance claim. The projection
reported 256 retained paths and 1,747 omitted paths explicitly.

The full symbol/reference map remains private infrastructure. The current
release does not use it to infer relevance, calls, or relationships in the
model-facing result.

### Causal Context Gateway

M-010 handles one common repository search:

```text
rg -n -C 8 -- <RustIdentifier> .
```

Codex and the model use this ordinary command; they do not call Cabal or perform
an extra step. The rewrite applies only to a `Bash` tool call made at the Git
worktree root, with one ASCII Rust identifier and no extra flags, paths, pipes,
redirects, or composed commands. For that exact form, the plugin silently runs
the same `rg` arguments in the same repository and captures the result locally.
It then groups repeated file paths while keeping every match and context record
unchanged. The grouped result replaces the original only when it is smaller.

The returned tool result contains the query and the same line-numbered source
records. It excludes the private request, lifecycle data, Git identity,
temporary files, measurements, executor output, and Cabal bookkeeping. M-010
does not add guessed definition, reference, test, call-graph, or relevance
labels. The hook API does not let the plugin prove whether Codex stores the
rewritten command itself in internal transcript history.

Unsupported syntax is left alone. A missing tool, stale request, size limit,
parse problem, plugin failure, or non-beneficial result causes the exact
original search to run with its normal output, errors, and exit code. On Linux,
this guarded path requires the standard `base64` command from coreutils.

In the frozen 36,199-byte source fixture, the search returned 432 source
records. M-010 retained all 432 and reduced the result from 43,435 to 38,715
UTF-8 bytes, or 10.87%. Across nine measured Windows runs, median execution time
was 13.002 ms for raw `rg` and 211.824 ms through the guarded projection. Exact
token counts are unknown because no tokenizer was used. The
[accepted aggregate](benchmarks/m010-causal-context-v1.json) links these numbers
to the frozen input digest and the exact 432-record preservation check. These
are fixture-specific measurements, not universal guarantees.

This is a narrow, verifiable reduction of repeated path text, not a claim that
Cabal intercepts every search or understands the full meaning of the code.

### Supporting Normalizers

- `cabal-observe`: Cargo/rustc JSON and textual test normalization.
- `cabal-delta`: captured unified Git diff normalization.
- `cabal-log`: JUnit XML, SARIF 2.1.0, nextest, and generic log normalization.
- `cabal-repository-map`: deterministic repository and Rust syntax facts.

## Requirements

- Rust nightly, edition 2024
- Windows 11 or Linux
- coreutils `base64` on Linux for the M-010 guarded projection path
- No `unsafe` code in the Cabal Runtime workspace
- Standard Codex CLI with plugin and hook support

## Install In Codex CLI

```powershell
cargo +nightly install --path crates/cabal-runtime-hook --force
codex plugin marketplace add .
codex plugin add cabal-runtime@cabal-runtime-local
```

Review and trust the installed hook through `/hooks` before ordinary use. The
`--dangerously-bypass-hook-trust` option is reserved for controlled validation
and is not part of normal operation.

## Validate

```powershell
cargo +nightly fmt --all -- --check
cargo +nightly test --workspace --all-targets
cargo +nightly clippy --workspace --all-targets -- -D warnings
```

CI runs the same workspace tests on Windows and Ubuntu. Repository-map tests
cover deterministic bytes, known symbols/imports/references/tests, qualified
methods, incremental reuse/change/delete, Cargo refresh, malformed and
oversized sources, projection leakage, bounds, corrupt indexes, Git
containment, symlink omission, exact rewrites, near misses, and the
context-effectiveness gate.

## License

Dual-licensed under MIT or Apache-2.0.

---

# Cabal Runtime: описание на русском

Cabal Runtime переносит объёмную, но однозначную техническую работу за пределы
контекста модели с помощью штатных обработчиков стандартного Codex CLI. Модель
продолжает использовать обычные команды. Для точно поддерживаемых вариантов
плагин сам выполняет операцию и возвращает краткий полезный результат вместо
полных журналов, содержимого изменений, повторно прочитанных файлов, служебных
данных или чрезмерно большого списка файлов.

Изменённая версия Codex не нужна. Модель не вызывает отдельный инструмент
Cabal, не загружает специальные инструкции и не выполняет дополнительных
действий.

## Как плагин устраняет контекстный мусор

1. Codex запрашивает обычную поддерживаемую команду.
2. Обработчик `PreToolUse` распознаёт только заранее определённую точную форму
   и через `updatedInput` незаметно направляет вызов в `cabal-runtime-hook`.
3. Сырые данные, хеши, полная карта и служебные пути остаются локально вне
   контекста модели.
4. Модель получает только нужные сведения, явное число пропусков и указание,
   полный ли это результат.
5. Неподдерживаемая команда не изменяется и исполняется штатным Codex.

Прозрачность действует только для перечисленных обработчиков и точных форм
команд. Проект не заявляет, что перехватывает любые команды оболочки, все
варианты `unified_exec`, операции MCP или неизвестные инструменты.

Ответы MemoryX, Safeguard, других серверов MCP, приложений Codex и сторонних
плагинов остаются без изменений. Cabal не сокращает, не заменяет, не подавляет
и не сохраняет их содержимое. Очистка контекста применяется только к явно
перечисленным ниже командам, за обработку которых отвечает сам Cabal.

## Реализованные модули

### Обработка Cargo

Простые `cargo build`, `cargo check`, `cargo clippy` и `cargo test` выполняются
через встроенный обработчик. Полный вывод компилятора и тестов остаётся в
локальных служебных файлах, исключённых из Git. Модель получает итог, коды
ошибок, важные сообщения, места ошибок в исходниках и сводку тестов без шума
процесса сборки.

### Обработка отчётов и журналов

Точные простые чтения отчётов JUnit, SARIF, nextest и обычных `*.log`, а также
простые `cargo nextest run`, преобразуются в краткую сводку. Полный тестовый
вывод, повторяющиеся строки и внутренняя структура отчёта не попадают модели.
Повреждённый отчёт никогда не объявляется успешным.

### Сводка изменений Git

Только `git status`, `git diff`, `git diff --cached` и ограниченный
`git show <revision>` преобразуются в пути, статусы, виды изменений, счётчики и
диапазоны изменённых строк. Полное содержимое изменений остаётся в служебном
каталоге Git. Дополнительные флаги, ограничения по путям, диапазоны версий,
перенаправление и составные команды не перехватываются.

### Повторное чтение файлов

Для точных ограниченных чтений UTF-8 через `cat`, `Get-Content` и узкую форму
`sed -n` плагин запоминает версию содержимого. Повторное чтение уже просмотренной
неизменённой части возвращает короткий статус `unchanged`. После изменения
возвращается актуальный запрошенный фрагмент и небольшой список изменённых
строк. Неподдерживаемые чтения выполняются как обычно.

### Проверка завершения

Необязательный `.cabal/completion/contract.json` проверяется обработчиком
`Stop`. Если файла нет или все условия выполнены, модель не получает новых
действий. Если подтверждение отсутствует, устарело, указывает на ошибку или
повреждено, Codex получает одно короткое указание продолжить работу.

### Ограничение изменений

Необязательный `.cabal/policy/change_policy.json` проверяет `apply_patch` и
ограниченный набор простых команд изменения до их исполнения. Разрешённая
операция не создаёт дополнительного вывода. Запрещённая получает штатный ответ
`permissionDecision: "deny"` с коротким кодом причины. Команды неизвестной
формы плагин не оценивает.

### Карта проекта

M-009 скрыто ведёт `cabal.repository_map.v1` в служебном каталоге Git. Карта
содержит версии и виды файлов, пакеты и цели Cargo, прямые зависимости, модули
Rust, определения, области видимости, подключения, синтаксические упоминания,
методы и тесты. Для разбора Rust используется библиотека `syn`. Повреждённые и
слишком большие исходники, превышение ограничений, ошибки Cargo и другие
пропуски всегда отмечаются явно; неполная карта не выдаётся за полную.

Карта обновляется без передачи содержимого модели при `SessionStart`, после
поддерживаемых операций редактирования и перед сокращением списка файлов, если
такой список будет меньше обычного. Для неизменённых файлов повторный разбор не
нужен; сведения об изменённых, добавленных и удалённых файлах обновляются.
`.git` исключён, символические ссылки не обходятся, а служебные данные нельзя
записать за пределами каталога Git.

Для точных `rg --files` и `rg --files .` плагин может незаметно вернуть
ограниченный `cabal.repository_inventory.v1`. Замена выполняется только если
результат меньше ожидаемого обычного списка. Поэтому в маленьком проекте
плагин не увеличивает контекст, а оставляет команду без изменений. Флаги,
другие аргументы, конвейеры, перенаправления и составные команды модуль не
перехватывает.

В локальном проверочном проекте на 2 003 файлах список занимал 118 038 байт
UTF-8, а сокращённый результат 15 990 байт: уменьшение на 86,45%. Это
проверочное измерение, а не универсальная гарантия. Результат явно сообщил 256
сохранённых и 1 747 пропущенных пути.

Полная карта символов и упоминаний остаётся внутренней. Текущий релиз не
использует её, чтобы приписывать найденному коду важность, связи или вызовы.

### Сокращение контекстного поиска

M-010 обрабатывает одну распространённую команду поиска:

```text
rg -n -C 8 -- <ИмяRust> .
```

Codex и модель используют обычную команду и не делают ничего специально для
Cabal. Замена применяется только к вызову инструмента `Bash` из корня рабочего
дерева Git: допускается одно имя Rust из символов ASCII, без дополнительных
флагов, путей, конвейеров, перенаправлений и составных команд. Если форма
совпала точно, плагин незаметно запускает тот же `rg` с теми же аргументами в
том же проекте и сохраняет полный результат локально. Затем он группирует
повторяющиеся пути к файлам, сохраняя каждую найденную строку и каждую соседнюю
строку без изменений. Сокращённый вариант используется только тогда, когда он
действительно меньше исходного.

Возвращаемый результат содержит искомое имя и те же строки исходного кода с
номерами. В нём нет внутреннего запроса, сведений о сеансе, состояния Git,
временных файлов, измерений, технического вывода исполнителя и служебных данных
Cabal. Модуль не добавляет предположения о том, где находится определение,
ссылка, тест, вызов или важный фрагмент. API обработчиков не позволяет плагину
доказать, сохраняет ли сам Codex изменённую команду во внутренней истории.

Команды другой формы плагин не меняет. Если отсутствует нужная программа,
запрос устарел, превышено ограничение размера, разбор не удался, возникла
ошибка или сокращение не даёт выгоды, выполняется точная исходная команда с её
обычным выводом, ошибками и кодом завершения. В Linux для этого защищённого
пути нужна стандартная команда `base64` из coreutils.

В зафиксированном проверочном файле размером 36 199 байт поиск вернул 432
строки исходного кода. M-010 сохранил все 432 строки и уменьшил результат с
43 435 до 38 715 байт UTF-8, то есть на 10,87%. В девяти измерениях на Windows
медианное время обычного `rg` составило 13,002 мс, а защищённого сокращения
211,824 мс. Точное число токенов неизвестно, потому что разметчик токенов не
применялся. [Принятый итог](benchmarks/m010-causal-context-v1.json) связывает
эти числа с хешем зафиксированного входного файла и точной проверкой сохранения
всех 432 строк. Эти числа относятся только к данному проверочному файлу и не
являются общей гарантией.

Это узкое и проверяемое уменьшение повторяющегося текста путей. Проект не
заявляет, что перехватывает любой поиск или полностью понимает смысл кода.

## Установка и проверка

```powershell
cargo +nightly install --path crates/cabal-runtime-hook --force
codex plugin marketplace add .
codex plugin add cabal-runtime@cabal-runtime-local

cargo +nightly fmt --all -- --check
cargo +nightly test --workspace --all-targets
cargo +nightly clippy --workspace --all-targets -- -D warnings
```

После установки новую точную версию обработчика необходимо один раз проверить
и разрешить через `/hooks`. Опция `--dangerously-bypass-hook-trust` предназначена
только для контролируемых тестов и не требуется при обычной работе.

Лицензия: MIT или Apache-2.0.
