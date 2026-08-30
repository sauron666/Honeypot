# ADR-010 — VMI observer (DRAKVUF/libvmi): agentless наблюдение вътре в примамката

Статус: приет, частично реализиран. Parsing/mapping е готов и тестван;
остава hypervisor-glue, който изисква Xen dom0 хардуер.

## Контекст

Пълните VM примамки (ADR, `internal/farm`, профил P4) са истински машини —
затова са неразличими от продукционен хост. Но емулираните услуги виждат само
до входната врата: NetNTLMv2 hash по SMB, парола по MySQL, команда по SSH.
Щом атакуващият е *вътре* в пълна VM, това, което прави там — процеси, файлове,
регистри, инжекции, изтриване на shadow copies — е невидимо за всичко останало
в MIRAGE.

Агент вътре в госта е грешният отговор: атакуващият, който притежава машината,
го намира и го изключва, и наблюдението, на което разчиташ, изчезва точно
когато има значение. Затова наблюдението трябва да е **agentless** — от
хипервайзора надолу, без нищо в госта. Това е и единствената причина пълна VM
примамка да си струва цената над емулирана.

DRAKVUF (на Xen, чрез libvmi + altp2m) прави точно това: трапва на ниво
хипервайзор и реконструира активността на госта без нищо инсталирано в него.

## Решение

`ObserverDriver` абстракцията (`internal/drivers/drivers.go`) вече има
`Observe(ctx, decoyID) -> <-chan Sighting`. `Sighting` е нормализираната форма,
която всеки observer произвежда; останалата част от MIRAGE не знае откъде идва.

Две имплементации (`internal/drivers/observer/`):
- **`none`** — честният избор без хипервайзор: не наблюдава нищо, не твърди
  никакви capabilities. Съществува, за да има категорията ≥2 имплементации и
  deployment без Xen да има валиден избор, а не липсваща способност.
- **`drakvuf`** — agentless VMI. Декларира `agentless`, `process`, `file`,
  `registry`, `memory_dump`, `crypto_hook`. Маркиран `Experimental`, докато не
  се валидира на реален Xen.

## Какво е готово (и тествано без хипервайзор)

1. **`drakvuf_parse.go`** — `ParseDrakvufLine`: превръща един ред DRAKVUF JSON
   (procmon, filedelete/filetracer, regmon, injection, ssdt/rootkitmon) в
   `Sighting`. Непозната plugin-а се пропуска, а не чупи потока — DRAKVUF добавя
   plugin-и постоянно. NT device пътища (`\Device\HarddiskVolume2\...`) се
   нормализират до четими. Тестван срещу реалната форма на изхода.
2. **`sighting.go`** — `SightingToEvent`: мапва `Sighting` към OCSF събитие с
   правилен severity и ATT&CK. Интерактивна команда вътре в примамка е `high`
   (T1059/T1057), инжекция е `critical` (T1055), Run-key запис е `high`
   (T1547.001), масово изтриване е `high` (T1485 — ransomware детекторът го
   подхваща). Планът е `PlaneObserver`, за да се различава от емулираните.
3. **`drakvuf.go`** — драйверът: `Observe` резолва decoy → Xen домейн, пуска
   `drakvuf -o json -d <domain>`, стриймва парснатите Sighting-и. Streaming
   цикълът е тестван с fake runner. `Probe` честно казва дали `drakvuf` е на
   PATH. Без резолвер `Observe` fail-closed, не гадае домейн.

## Какво остава (hypervisor-only glue) — това ще довърша на Xen хост

1. **decoy → Xen домейн резолвер.** `Drakvuf.SetDomainResolver` се извиква от
   `internal/app` с функция, backed от compute драйвера (libvirt/`xl list`),
   която дава домейн името и rekall/volatility профила за примамката. Сега е
   стъб, който отказва.
2. **Валидация на `execCommandRunner` срещу истински `drakvuf`.** Спускането,
   буферирането и killването на процеса при отказан контекст са написани, но
   не са пускани срещу реалния бинар. Форматът на аргументите (`-r <profile>`,
   `-o json`) трябва да се потвърди спрямо инсталираната версия.
3. **`DumpMemory`** — през `drakvuf` memdump или `vmi-dump-memory`. Стъб сега.
4. **`crypto_hook`** — DRAKVUF може да лови ключове (напр. при ransomware
   криптиране). Мапингът за `Kind:"crypto"` трябва да се добави в `sighting.go`,
   след като видя реалната форма на плъгина на хардуер.
5. **Wiring в `app.go`** — когато `drivers.observer` е зададен и има VM примамки,
   `app` вика `Observe` за всяка стартирала примамка и подава Sighting-ите през
   `SightingToEvent` в шината (`a.ingest`). Дълготраен горутинен цикъл, спрян
   при `farm` burn/revert.
6. **Deeper `Probe`** — Xen present, altp2m наличен, dom0 привилегии.

## Как да се довърши (за бъдеща сесия на Xen dom0)

```
# предпоставки на хоста: Xen, drakvuf, libvmi, профил за госта
drakvuf -o json -d <domain>        # потвърди формата на изхода
```

1. Пусни съществуващите тестове (`go test ./internal/drivers/observer/`) —
   parsing/mapping вече е зелено.
2. Имплементирай резолвера през libvirt драйвера, махни стъба в `NewDrakvuf`.
3. Пусни `drakvuf` срещу истинска P4 примамка; сравни реалните редове с
   `ParseDrakvufLine` и коригирай ключовете, ако версията се различава.
4. Добави crypto мапинга и `DumpMemory`.
5. Wire-ни в `app.go`; тествай с истинска атака вътре в примамката.
6. Махни `Experimental`, обнови README „какво работи".

Понеже parsing/mapping е изолиран и тестван, hardware сесията е предимно
интеграция и валидация, не дизайн.

## Жива валидация (2026-08-30)

DRAKVUF v1.1 **тръгна живо** на реален хардуер: **i5-1035G1 (Ice Lake, VMFUNC ✓)**,
**Xen 4.20**, Debian 13 dom0. Парсерът е валидиран срещу истинския JSON изход и
`ParseDrakvufLine` вече го покрива. Ключови находки от живото пускане:

- **Linux guest → само process listing.** DRAKVUF емитира `RunningProcess`
  (инвентар на вече вървящите процеси), без `ProcessName`/`UserId`/`TID`/
  `CommandLine`. Тези triggered полета идват от **Windows kernel hooks**
  (syscall/filetracer плъгините не закачат нищо на Linux → 0 събития). Парсерът
  третира listing-а като informational инвентар, не като аларма.
- **За пълна интроспекция** (exec, file delete, registry, injection) е нужен
  **Windows guest + Windows ISF профил** (генериран с `vmi-win-guid` /
  volatility срещу самия guest). Това е единствената оставаща стъпка за пълно
  VMI; изисква Windows VM на Xen.
- **Xen 4.20 капани:** `altp2m=1` в командния ред (не `=mixed`); domain config
  `altp2m = "external"` (не `"mixed"`); libvmi config ключ `volatility_ist`
  (не `json_path`). При crash: vm_event lock → `xl destroy` + `xl create`.
- **Хардуер:** i3-9100T (Coffee Lake) няма VMFUNC → DRAKVUF не тръгва; Ice Lake+
  го има. libvmi и `vmi-dump-memory` работят и без VMFUNC.

Остатъчна стъпка за пълно VMI: Windows guest + ISF профил. Всичко останало е
живо потвърдено.

## Последици

Deployment без хипервайзор губи нищо — `none` е валиден и честен. Deployment с
Xen получава наблюдение, което атакуващият не може да намери или изключи, и
което захранва ransomware детектора и engagement историята със сигнали отвътре.
