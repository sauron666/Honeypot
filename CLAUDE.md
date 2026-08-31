# MIRAGE — работно състояние и конвенции

> Този файл се чете автоматично в началото на всяка сесия. Той е паметта на
> проекта: къде сме, какво не бива да се нарушава, какво следва. Ако нещо в
> него не отговаря на кода — кодът е прав, файлът се обновява.

**Какво е:** платформа за deception (honeypot/honeynet). Пълният план е в
`docs/`; този файл е оперативното резюме.

**Клон за работа:** `claude/honeypot-software-plan-c9txsh`. Пуш след всеки
завършен етап.

---

## 1. Състояние към последния commit

Работещ продукт в профил P0 („honeypot в кутия"): един бинар вдига примамки,
записва всичко в tamper-evident chain, стичва го в engagement-и, вдига аларми
и го показва в комерсиална операторска конзола. ~42 300 реда Go, ~12 550 от
тях тестове (401 тестови функции). 32 тестови пакета.

**Proxmox REST API драйвер** работи дистанционно (без pvesh) — ticket auth,
API token, TLS fingerprint pinning. Cloud-init Ubuntu 24.04 шаблон (VMID 9000)
създаден на PVE 8.4.

**DRAKVUF observer glue завършен.** Пълният код е готов: config→app→observer
wiring, domain resolver от compute драйвера, Observe горутини за VM примамки,
сигнали през ingest, DumpMemory (vmi-dump-memory / xl dump-core), crypto hook
(apimon/BCryptEncrypt→T1486), Probe за Xen dom0 (/proc/xen/capabilities + xl),
API endpoint-и (GET /api/observer, POST /api/observer/{id}/dump), GUI секция.
**Парсерът е валидиран срещу DRAKVUF v1.1 сорс код** (jsonfmt.h) — TimeStamp
е quoted string, UserId е int, filedelete2 е текущият plugin. libvmi и
vmi-dump-memory работят на Xen 4.17 HVM domU. **За пълна DRAKVUF интроспекция
е нужен CPU с VMFUNC** (altp2m) — i3-9100T го няма.

**GUI** — 20-секционен SPA: dashboard, engagements, events, decoys, honeytokens,
full-OS VMs, images, detection rules, evidence chain, compliance, **observer/VMI**,
**ransomware trap**, **topology**, presence, **deception packs**, **identity/BEC**,
**BYOD/wireless**, **global feed**, config, status. VM секцията има start/stop
бутони; compliance секцията чете от `/api/compliance/{framework}`; topology
секцията рисува цялата естейт като инлайн SVG звезда (director→decoys/vms/hub/
agents) от `/api/topology`. **Всяка таблица се сортира** (MutationObserver
прави всеки `table.tbl` кликаем по колона). **Decoys секцията има builder** —
форма за добавяне/редакция (POST /api/decoys, merge по id през същия reconcile)
и „retire" бутон (DELETE /api/decoys/{id}); tokens секцията вече имаше mint/delete.
**Token auth в GUI**: Bearer от localStorage + cookie `mirage_token`; login
overlay при 401; статиката е exempt (иначе токенът заключваше конзолата).
50 REST endpoint-а.

**Туториали** — `docs/tutorials/` (14 броя, български): quickstart, конзола,
honeytokens, детекции, VM декои, VMI, overlay, AD/Kerberos, breadcrumbs,
доказателства+vault, compliance+export, **ransomware trap**, **библиотека с
образи**, **хипервайзори**. Всеки показва GUI и
CLI, където има смисъл. **Научен труд** за trap-а: `docs/research/ransomware-tarpit.md`.

**Ransomware trap (hypervisor-agnostic)** — `internal/fusetrap`. DRAKVUF иска
Xen+VMFUNC; повечето клиенти карат KVM/VMware/Hyper-V. Trap-ът затваря дупката за
най-важната заплаха без VMI: FUSE bait дял, всяка операция минава през детектора
и tarpit-а преди диска. Потвърждение за 2-3 операции, snapshot на декоя, critical
T1486 в веригата. Config секция `trap:`, GUI секция „Ransomware Trap",
`GET /api/trap`. Портируемият мозък е тестван на всяка платформа; FUSE монтажът
е Linux-only (best-effort — mount провал не спира director-а).

**Платформи:** компилира се и минава тестове на Linux и Windows. На Windows
Unix file permissions не се проверяват (не съществуват); тестовете го пропускат
с `runtime.GOOS` guard.

```bash
make build
./bin/miragectl doctor --config profiles/p0-box.yaml
./bin/mirage-director --config profiles/p0-box.yaml   # конзола: 127.0.0.1:8422
```

### Пакети

| Пакет | Какво прави |
|---|---|
| `internal/event` | OCSF събитие, ULID, канонична сериализация, **append-only hash chain** |
| `internal/store` | append-only JSONL evidence, resume след рестарт, стрийм проверка |
| `internal/bus` | шина, NATS-съвместим subject matching; `Close()` изчаква handler-ите |
| `internal/drivers` | осемте абстракции + registry с capabilities (ADR-008) |
| `internal/drivers/compute` | `inproc`, `podman`, `libvirt`, `proxmox` (REST + pvesh), `vsphere` (vCenter REST, **experimental**), `hyperv` (PowerShell/SSH, **experimental**) |
| `internal/drivers/sink` | `stdout`, `file`, `webhook`, `syslog`, `elastic` (ECS), `splunk` (HEC) |
| `internal/driverset` | регистрация на вградените драйвери (отделен пакет заради import cycle) |
| `internal/honeyd` | фермата: 15 протокола, персони, виртуална ФС, shell, reconcile |
| `internal/engagement` | стичане на събития в една история; `FromEvents` за офлайн възстановяване |
| `internal/alert` | праг по severity, дедупликация, линк към engagement, synthetic маркер |
| `internal/tokens` | honeytokens: 8 типа, callback, watcher, .docx генератор |
| `internal/ransomware` | шест сигнала за криптор, tarpit, извличане на контакти от бележката |
| `internal/fusetrap` | **hypervisor-agnostic ransomware trap**: FUSE bait дял → детектор + tarpit + snapshot-on-confirm; портируем мозък (тестван навсякъде) + Linux FUSE binding (go-fuse) зад build constraint |
| `internal/catalog` | **библиотека с образи**: JSON регистър (референцира по път), difficulty tiers (easy/med/hard/insane), формат от разширението, sanitisation planner (чист) + applier през virt-customize (probe, честен ако липсва); не трие файлове, не дистрибутира HTB образи |
| `internal/packs` | **Deception Packs**: подписани (ed25519), версионирани пакети с персони/декои/honeytokens/lures; вградени (healthcare-de, finance-en); валидират се срещу реалните персони |
| `internal/saasid` | **SaaS/identity deception** (idea 11): honey Entra/Okta/Workspace идентичности + audit-log matcher; IdP push е бъдещ driver |
| `internal/bec` | **email/BEC deception** (idea 12): honey финанс идентичности + AnalyzeEmail (кампания IOCs, spoofed-exec tell) |
| `internal/analyst` | **LLM аналитик** (idea 18): офлайн Template + опционален локален LLM (OpenAI-съвместим); никога в alerting, всичко RequiresReview |
| `internal/feed` | **global feed** (idea 19): Anonymize маха IP/tenant/токени, пази TTP-та; подписан ed25519, merge с дедуп |
| `internal/wireless` | **BYOD deception** (idea 20): honey mDNS/DNS-SD устройства + recon детектор; SSID/BLE/karma искат RF хардуер (честно) |
| `internal/forge` | генериране на Sigma/Suricata/YARA/STIX + инцидентен доклад |
| `internal/assure` | самотест на веригата + **Detectability Score** (fingerprint) |
| `internal/config` | YAML манифест, валидация, `plan` диф, immutable настройки |
| `internal/app` | сглобяването на едно място (бинарът и e2e тестовете ползват него) |
| `internal/presence` | overlay: хъб + Presence Agent, тунел с мултиплексиране, взаимен TLS + собствен CA (`ca.go`) |
| `internal/life` | синтетичен живот: детерминистичен график на логини/логове/lastLogon като функция на времето; примамката изглежда все по-обитаема при всяка проверка |
| `internal/farm` | пълни VM примамки: provisioner, containment gate, baseline, revert, burn, start/stop |
| `internal/drivers/fabric` | `nftables` (налага + чете правилата), `probe` (тества реалната достижимост) |
| `internal/drivers/observer` | `none` (честен no-op) + `drakvuf` (agentless VMI, Xen) + `agent` (in-guest сензор, всеки хипервайзор; приемник + fan-out per-decoy, token auth, drop-on-overflow; НЕ декларира CapAgentless) |
| `internal/api` | REST (50 endpoint-а) + вградена конзола (`internal/api/web/` — 20-секционен SPA); 40 теста: auth (Bearer+cookie, статика exempt), CSP, XSS escape, decoy builder (merge/edit/remove), packs/saasid/bec/wireless/feed, всеки endpoint без зависимости |
| `internal/breadcrumbs` | подхвърля примамки-следи на реален endpoint, които водят към декоите: .rdp, ~/.aws, ssh config, история; honeytoken във всяка, обратимо чрез манифест |
| `internal/drivers/nac` | `none` (честен no-op) + `freeradius` (RADIUS CoA — насочва непознато устройство към deception VLAN вместо да го блокира) |
| `internal/graph` | `mirage-graph` — attack-path deception; поставя примамки по вероятните пътища на атаката |
| `internal/toolkit` | Attacker Toolkit DB — fingerprint на инструменти и предсказване на следваща стъпка |
| `internal/insider` | insider-threat kit: vertical-специфични honey документи + DPIA/policy шаблони (правна рамка) |
| `internal/compliance` | одит срещу NIS2/DORA/ISO 27001/PCI/SOC2/IEC 62443; способност→контроли, markdown доклад |
| `internal/export` | STIX 2.1 bundle, TheHive alert, дедупликиран IOC списък (MISP/OpenCTI/TheHive) |
| `internal/watermark` | watermarking и проследяване на изтичане на подхвърлено съдържание |
| `internal/fleet` | авто-ротация на идентичности (чиста функция на времето; отлага при активен engagement, пропуска изгорени) |
| `internal/replay` | SSH session replay в asciinema v2 формат |
| `internal/vault` | подписани доказателства: ed25519 seal на chain head + RFC 3161 trusted timestamp; прави веригата проверима от трета страна (съд/одитор) |
| `internal/drivers/compute` (proxmox) | добавен `proxmox` драйвер към `inproc`/`podman`/`libvirt` |
| `cmd/mirage-director`, `cmd/miragectl`, `cmd/mirage-presence`, `cmd/mirage-breadcrumbs`, `cmd/mirage-sensor` | бинарите. `miragectl` изкарва всичко: doctor/plan/apply/verify/events/forge/tokens/assure/fingerprint/vms(+smoketest)/images/**packs**/presence-ca/economics + **export/compliance/insider/fleet/graph/toolkit/watermark/replay/vault** + **saasid/bec/analyst/feed/wireless**. `mirage-sensor` е in-guest колекторът (Linux netlink / Windows Sysmon → agent observer) |

### Протоколи (`internal/honeyd/svc_*.go`)

`ssh` (истински, x/crypto), `ldap` (фалшива AD), `kerberos` (истински KDC:
enumeration, spraying, AS-REP roast и kerberoast с crackable RC4-HMAC hash),
`smb` (NetNTLMv2 улов), `http`, `telnet`, `ftp` (+ransomware engine), `redis`,
`mysql` (верифицира подхвърлена парола от скрамбъла), `mssql` (възстановява
паролата в чист текст), `vnc`, `smtp`, `snmp` (UDP), `modbus` (ICS), `mcp`
(honey MCP/AI сървър — AI/LLM deception), `tarpit` (LaBrea-style sticky —
trickle банер, задържа скенера, отчита погълнато време; idea 15), `tokens`
(callback приемник), `generic`. **18 регистрирани услуги** (`RegisterService`).

**Staged (нарочно unwired):** `internal/honeyd/jit.go` (JITSpawner — реактивно
спуска временна услуга при probe на well-known порт). **Не е wire-нат** в server-а
(нула callers) — включва се по-късно при нужда. Вече има **scan guard**
(`scanGuard`): източник, който удря ≥ScanThreshold различни порта в ScanWindow, се
маркира като скенер и се потиска за cooldown — nmap sweep НЕ вдига декой на всеки
порт (+ MaxActive hard cap). `OnProbe(ctx, sourceIP, addr, port)`. 5 теста за
guard-а. Не се трие — етапна работа със защита готова за включване.

### Персони (`internal/honeyd/persona_*.go`)

`linux/web`, `linux/db`, `linux/backup`, `linux/fileserver` (генериран дял с
canary файлове), `windows/dc` (AD с kerberoast/AS-REP/ADCS/LAPS примамки).

---

## 2. Инварианти — не се нарушават

1. **Containment преди функционалност.** Примамка никога не набира навън и
   никога не изпълнява нищо. `wget`/`ssh`/`nc` в shell-а връщат правдоподобен
   отказ + IOC събитие. UDP отговорите са ограничени срещу amplification
   (виж `amplificationSafe` в `server.go`). Има тестове точно за това.
2. **Нула вендори в ядрото** (ADR-008). Вендорски пакет само в
   `internal/drivers/<vendor>/`. Всяка категория с ≥2 имплементации —
   `driverset` тестът го проверява.
3. **Append-only доказателства.** Събитие веднъж записано не се променя.
   `store.Verify` открива промяна, изтриване и разместване.
4. **Нищо не се вмъква като HTML в конзолата** — само текстови възли.
   UI-ът рендерира съдържание, контролирано от атакуващия.
5. **Detection изходът е сдържан.** `forge` отказва да прави правило от `ls`
   или от нормален browser user agent и публикува защо.
6. **Честност в README.** Ако нещо не е валидирано (SMB файлови операции,
   VMI), се пише изрично, не се твърди.

---

## 3. Капани, в които вече сме падали

- **`_windows.go` / `_linux.go` са implicit build constraints.** Файлът се
  компилира само на тази платформа и нищо не се чупи. Има тест-guard:
  `test/e2e/build_constraints_test.go`.
- **`pkill -f mirage-director` убива собствената shell сесия**, защото
  командният ред я съдържа. Ползвай `pgrep -x mirage-director | xargs -r kill`.
- **Toolchain:** винаги `GOTOOLCHAIN=local` (иначе тегли нов Go).
- **Port 0 в тестове** е ефемерен и не може да се реконсилира — reconcile
  тестовете подават явни портове (`freeTestPort`).
- **`bus.Close()` трябва да изчака** subscriber горутините, иначе handler-и
  пишат след „stopped cleanly".
- **`apply` трябва да реинжектира runtime опциите** (host key path, token
  lookup), иначе новите listener-и се вдигат счупени.
- **Мултиплексорът не бива да блокира read цикъла.** Доставката на данни към
  поток минава през буфериран канал; директно писане в pipe заключва целия
  тунел (head-of-line). При препълване потокът се затваря, не се блокира.
- **Затварянето на поток не бива да изхвърля недоставените данни** — отговор,
  който вече е пристигнал, се губи, защото peer-ът отговаря и затваря наведнъж.
- **`Hub.Close()` трябва да затвори и приетите сокети**, не само listener-а,
  иначе изчаква дълги read deadline-и.
- **`streamConn` трябва да спазва deadline-ите.** Всяка емулирана услуга слага
  read deadline, за да изхвърли атакуващ, който мълчи. Докато `SetDeadline`
  беше no-op, тунелирана сесия висеше, докато атакуващият държи сокета, и
  тунелът свършваше поточните id-та. `Read` селектира върху данни, таймер и
  `wake` канал, който `SetDeadline` затваря — иначе вече блокиран `Read` не
  вижда новия срок (net.Conn обещава, че го вижда).
- **`Agent.Close()` не бива да чака backoff-а.** Без `done` канал спирането на
  агент, който току-що е загубил хъба, отнемаше цял `reconnect_max`. Тестът
  `TestAgentFailsClosedWhenTheTunnelIsDown` падна от 20s на под секунда.
- **Пълна VM примамка не тръгва без проверен containment.** `farm.Provisioner`
  пита fabric драйвера преди първия старт; без fabric драйвер отказва, освен
  ако `vms.containment: unenforced` не е зададено изрично (и тогава го записва
  като събитие). Няма трети вариант — VM, който атакуващият превзема, е
  истински хост в мрежата на клиента.
- **Изгорена примамка не се рециклира и не се трие.** Нито при `revert`, нито
  при reconcile, нито когато я махнеш от манифеста. Тя е доказателството.
- **`revert` първо снима мръсното състояние.** Ако снимката се провали, revert
  се отказва — по-добре мръсна примамка, отколкото изгубено доказателство.
- **Baseline се взима след като машината е вдигната**, не от студен образ:
  иначе всеки reset струва видимо буутване.
- **Reset става само след затворен engagement**, не по таймер. Рестарт, докато
  атакуващият е вътре, е най-очевидният tell, който изобщо може да се даде.
- **Kerberos е и TCP, и UDP на порт 88.** Клиентите пробват UDP и падат към TCP,
  когато отговорът не се събира. `ListenerConfig.Protocol` избира транспорта;
  KDC-то се декларира два пъти на 88. По UDP всеки съществен отговор е
  `KRB5KRB_ERR_RESPONSE_TOO_BIG` (без e-text — иначе е amplification), което е
  и каквото истински KDC връща.
- **Планираните пароли трябва да са crackable.** AS-REP/TGS blob-овете са
  истински RC4-HMAC над истински DER, с NT hash на планирана парола с формата,
  който хората избират. Ако паролата е случайна, hashcat не я намира и
  атакуващият разбира, че акаунтът е фалшив. Стойността е в reuse-а: watcher-ът
  свързва офлайн крака с онлайн опита.
- **Един каталог, два изгледа.** LDAP и Kerberos четат от `buildHoneyDirectory`;
  ако svc_sql се вижда по LDAP, но не се roast-ва по Kerberos, атакуващият е
  намерил шева. `TestKerberosBaitAgreesWithWhatLDAPAdvertises` го пази.
- **Торнат последен ред след kill не спира старта.** Крах/kill по средата на
  append оставя частичен последен ред; `store.replay` го отрязва (torn tail) и
  продължава веригата от последното трайно събитие — но повреда в СРЕДАТА на
  файла (пълен ред, който не декодира) пак гърми, защото е подправяне.
  `RecoveredBytes()` го докладва, `app` логва WARN. Открито при живия AD тест.
- **RADIUS CoA трябва да е подписан.** Request Authenticator = MD5(header+16
  нули+attrs+secret); без него FreeRADIUS дропва пакета тихо, а драйверът мисли,
  че е успял. CoA адресът е host(Server):CoAPort, не Server:CoAPort. Отговорът
  се чете и валидира (NAK/грешен secret = грешка).
- **Воден знак се вгражда винаги, не само при дълъг текст.** `embedZeroWidth`
  слага всичките 16 бита (между думите + остатъка накрая), иначе къс документ
  остава непроследим, а операторът не разбира.
- **Breadcrumbs пише на чужда машина — затова не разрушава.** Никога не
  презаписва съществуващ файл (O_EXCL за нови, fenced append за съществуващи);
  всеки crumb носи регистриран honeytoken (не истинска тайна); манифест пази
  какво е поставено, за да се махне точно то. `Remove` възстановява реалния
  файл байт-за-байт. Тестовете го доказват (append+remove round-trip, rollback).
- **Синтетичният живот е чиста функция на времето, не горутина.** `internal/life`
  не мутира нищо и не пази състояние: `Logins(now)` изчислява графика от seed-а.
  Затова няма race с четенето от атакуващия, историята е стабилна между две
  четения и напредва само когато `now` мине следващото събитие. Метроном
  (нов ред всеки N секунди) е по-силен tell от липсата на живот — затова всичко
  е jitter-нато от seed-а. И най-важното: **не емитира събития**, за да не влезе
  синтетична активност в доказателствената верига като атакуващ.
- **TLS ръкостискането се прави явно в `serveAgent`.** Оставено на първия
  `Read`, проблем със сертификат излиза като „връзката не започна с hello",
  което праща човека, който вдига mTLS, точно в грешната посока.
- **Proxmox REST API ticket-ът изтича.** `pveAPI.authenticate()` кешира
  ticket-а за 90 минути и го обновява автоматично. При API token auth не се
  изисква refresh. `verify_tls: false` по подразбиране (self-signed PVE certs).
- **GUI-ят не ползва innerHTML.** Всичко е `textContent` / `el()` helper.
  Атакуващият контролира командите, user agent-ите и пътищата, които се
  показват — XSS в операторската конзола би бил катастрофален.
- **Observer-ът се закача след Reconcile, не преди.** VM примамката трябва
  да е running, преди Observe да пусне DRAKVUF срещу нея. Ако примамката
  не е вдигната, domainOf ще fail-не и горутината умира. Спирането е
  обратното: `stopAllObservers()` преди `Farm.Close()`.
- **Crypto hook (apimon) е critical, не high.** Криптиране вътре в примамка
  без легитимен потребител е ransomware, докато не се докаже друго. T1486.
- **DRAKVUF иска VMFUNC (altp2m), не само VT-x.** `xl dmesg` показва
  `VMFUNC` и `#VE` като отделни CPU feature-и. i3-9100T (Coffee Lake-S)
  ги няма, въпреки че има EPT. Без altp2m DRAKVUF не може да постави
  shadow page table hooks. libvmi и vmi-dump-memory работят и без VMFUNC.
- **DRAKVUF TimeStamp е quoted string, не bare float.** `jsonfmt.h` печата
  `'"' << tv_sec << '.' << padded_usec << '"'`. Go's `encoding/json` декодира
  quoted число като string, не float64 — custom UnmarshalJSON е задължителен.
- **DRAKVUF няма UserName — полето е UserId (int).** `get_common_data()` в
  jsonfmt.h emit-ва `UserId` (числов UID/SID), не текстово потребителско име.
- **DRAKVUF на Linux генерира само listing, не triggered events.** `procmon`
  emit-ва `RunningProcess` (обхождане на task_struct); `syscalls` и `filetracer`
  не закачат нищо (0 събития). Triggered events с `ProcessName`/`UserId`/`TID`/
  `CommandLine` идват само от Windows guests. Парсерът приема и двата формата
  с fallback: `ProcessName` > `RunningProcess`.
- **Xen 4.20 altp2m=1, не altp2m=mixed.** Boot параметърът `altp2m=mixed`
  е невалиден в Xen 4.20 (rc=-1). Domain config `altp2m = "external"` (не
  `"mixed"`, което гърми с HVM_PARAM_ALTP2M грешка).
- **libvmi config ключ е `volatility_ist`, не `json_path`.** flex/bison
  парсерът в libvmi не разпознава `json_path` — получаваш "unknown config
  key" без ясно съобщение. ISF профил от dwarf2json се подава с `volatility_ist`.
- **`agent` observer-ът НЕ декларира CapAgentless — нарочно.** Има сензор в
  госта; честността е инвариант. DumpMemory е unsupported (хипервайзорно ниво).
  Токенът е задължителен (отворен ingest = liability). Fan-out per-decoy е
  buffered + drop-on-overflow — флудещ сензор не блокира director-а (както
  presence мултиплексора). `mirage-sensor` колекторите (netlink/Sysmon) не се
  тестват в CI (искат root/Windows+Sysmon); forwarder-ът е тестван. Пуска се на
  Xen с DRAKVUF (нулев tell), навсякъде другаде с този сензор.
- **vsphere/hyperv драйверите са Experimental — казва се явно.** `Info().
  Experimental=true` и Summary-то го пише. Unit-тествани срещу синтетичен
  vCenter (httptest) и fake runner, но НЕ на жив хипервайзор. Има тест, който
  гърми, ако някой махне флага. Не се твърди, че са field-proven (за разлика от
  proxmox на PVE 8.4). `Create` при двата е **adopt-first**: осиновява
  съществуваща VM по име, преди да клонира — честият workflow е операторът да
  пре-създаде декоя, а MIRAGE да го управлява.
- **Ransomware trap монтажът е best-effort.** `startTrap` логва warning и
  продължава при провал (не Linux, няма `/dev/fuse`, зает mountpoint) — director,
  който отказва да тръгне заради зает mountpoint, е по-лош от такъв без trap.
  Детекторът работи и през емулираните FTP/SMB услуги независимо.
- **Trap callback-ите се fire-ват без trap lock-а.** FUSE handler-ът е нишката
  на атакуващия; писане в evidence store-а под lock-а би заключило файловата
  система. `observeLocked` освобождава lock-а преди OnEvent/OnConfirmed.
- **`fs_linux.go` е нарочно Linux-only** (FUSE ядрена връзка, go-fuse). В
  allow-list-а на `build_constraints_test.go` е, с обосновка. Портируемият мозък
  (`trap.go`) компилира и се тества навсякъде; `fs_other.go` е стъб.
- **ConfirmScore=70, а ентропия+extension+velocity=65 нарочно.** Криптиране на
  чисто нови файлове (без разрушаване на познат тип и без canary) не стига за
  потвърждение само по себе си — иначе потребител, който твори нови файлове,
  би вдигнал аларма. Magic-loss или canary touch (+25) прехвърля прага. Това е
  съзнателен FP компромис, не бъг.
- **vm_event lock при DRAKVUF crash/timeout.** Ако DRAKVUF не се изключи
  чисто (timeout, kill), vm_event остава заключен — следващото стартиране
  гърми с "Device or resource busy". Единственият fix е `xl destroy` + `xl
  create`.

---

## 4. Работен процес

```bash
GOTOOLCHAIN=local go build ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local gofmt -l $(git ls-files '*.go')
GOTOOLCHAIN=local go test -count=1 -race ./...      # ~90s, всичко трябва да е ok
```

- Тестовете на `internal/honeyd` са бавни (~50s) заради нарочните забавяния
  при отказана автентикация — това е фийчър, не бъг.
- Commit съобщения: на български, обясняват **защо**, не какво. Всеки завършен
  етап се пушва.
- Всеки нов протокол/фийчър идва с тест, който доказва детекцията, и с тест за
  containment, ако пипа мрежата.

---

## 5. Какво следва (по приоритет)

1. ~~**Образи за VM примамките**~~ ✓ — cloud-init Ubuntu 24.04 шаблон
   (`templates/ubuntu2404-cloud/build-template.sh`), тестван на PVE 8.4.
2. ~~**Proxmox драйвер**~~ ✓ — REST API клиент, работи дистанционно.
3. ~~**Комерсиален GUI**~~ ✓ — 20-секционен SPA, 50 API endpoint-а, сортиране
   на всяка таблица, form-driven decoy builder (add/edit/retire), token auth
   (Bearer+cookie, статика exempt), секции за packs/identity/BEC/wireless/feed.
4. ~~**VMI observer — hypervisor glue**~~ ✓ — пълен glue: config→app wiring,
   domain resolver, Observe горутини, DumpMemory (vmi-dump-memory/xl), crypto
   hook (apimon→T1486), Xen Probe (/proc/xen + xl), API endpoint-и, GUI секция.
   16 теста. **Парсерът е валидиран живо срещу реален DRAKVUF изход.**

   **Xen валидация (2026-08-30):** Xen 4.20 (Debian 13) на Dell Inspiron 5401
   (i5-1035G1, Ice Lake — има VMFUNC). libvmi компилиран, `vmi-process-list`
   работи. DRAKVUF v1.1 компилиран и **тръгва живо** — altp2m=external, HVM
   guest с debootstrap + ISF профил (dwarf2json, 51 MB). Парсерът е
   **live-validated**: поправен за RunningProcess (listing формат vs. ProcessName
   за triggered events).

   **Живо откритие (Linux guest):** На Linux guest DRAKVUF генерира само process
   listing (RunningProcess формат, без UserId/TID/CommandLine). Triggered events
   (ProcessName/UserId/TID) идват от Windows kernel hooks (syscalls/filetracer
   плъгините на Linux не закачат нищо — 0 събития).

   **Windows валидация (2026-08-31):** Windows Server 2025 (build 26100) HVM guest
   на Xen 4.20 с `altp2m = "external"`. ISF профил генериран от PDB на
   ntoskrnl.exe (volatility3 pdbconv). **Пълна VMI интроспекция работи:**
   11 533 registry events (regmon), 190 file events (filetracer), 230 triggered
   process events (procmon с ProcessName/UserId/TID/CommandLine) за 80 секунди.
   Парсерът валидиран и срещу двата формата: listing (RunningProcess — inventory)
   и triggered (ProcessName — атакуващо действие). Syscall/sysret plugin-ите са
   нарочно пропуснати (хиляди в секунда — прекалено шумни за evidence chain).

   **Важно за средата:** DRAKVUF изисква **Xen + CPU с VMFUNC** (altp2m).
   i3-9100T (Coffee Lake) го няма; i5-1035G1 (Ice Lake) го има. VM примамките
   работят на Proxmox (KVM/QEMU), но agentless VMI иска Xen dom0 на CPU
   с EPT+VMFUNC. Xen 4.20 ползва `altp2m=1` (не `=mixed`), domain config
   ползва `altp2m = "external"` (не `"mixed"`). libvmi config ключът е
   `volatility_ist` (не `json_path`).
5. ~~**mirage-vault**~~ ✓ — ed25519 seal на chain head + опционален RFC 3161
   timestamp (`miragectl vault seal|verify`). Веригата вече е проверима от трета
   страна: подписът казва „това е от това внедряване", timestamp-ът — „съществуваше
   тогава". Tamper на файла проваля verify.
6. **Multi-tenancy, SSO/SAML** — за MSSP канала.
7. **Plugin SDK** — gRPC, HashiCorp go-plugin модел.
8. ~~**Допълнителни compute драйвери**~~ ✓ (structure) — `vsphere` (vCenter REST)
   и `hyperv` (PowerShell/SSH) добавени, маркирани **experimental**: unit-тествани
   срещу синтетични отговори, остава валидация на жив хипервайзор. libvirt/KVM и
   proxmox покриват KVM пътя. **Ключово:** ransomware trap-ът и мониторингът
   работят на всеки хипервайзор независимо от compute драйвера.

Отхвърлени съзнателно (виж `docs/11-IDEAS.md`): hack-back, автоматично
блокиране на IP към прод firewall, cloud-only контролер.

---

## 6. Документация

`docs/00`–`docs/11` са планът: визия, архитектура, компоненти, каталог на
измамата, containment/правна рамка, модел на данните, профили на внедряване,
роудмап, стек, бизнес, интеграции, идеи. `docs/adr/` — решенията с обосновка.
