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
и го показва в комерсиална операторска конзола. ~40 200 реда Go, ~10 000 от
тях тестове. 29 тестови пакета.

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

**GUI** — 13-секционен SPA: dashboard, engagements, events, decoys, honeytokens,
full-OS VMs, detection rules, evidence chain, compliance, **observer/VMI**,
presence, config, status.
34 REST endpoint-а (10 нови: compliance, graph, topology, VM start/stop, system,
fingerprint, observer status, observer dump).

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
| `internal/drivers/compute` | `inproc`, `podman`, `libvirt`, `proxmox` (REST API + pvesh CLI fallback) |
| `internal/drivers/sink` | `stdout`, `file`, `webhook`, `syslog`, `elastic` (ECS), `splunk` (HEC) |
| `internal/driverset` | регистрация на вградените драйвери (отделен пакет заради import cycle) |
| `internal/honeyd` | фермата: 15 протокола, персони, виртуална ФС, shell, reconcile |
| `internal/engagement` | стичане на събития в една история; `FromEvents` за офлайн възстановяване |
| `internal/alert` | праг по severity, дедупликация, линк към engagement, synthetic маркер |
| `internal/tokens` | honeytokens: 8 типа, callback, watcher, .docx генератор |
| `internal/ransomware` | шест сигнала за криптор, tarpit, извличане на контакти от бележката |
| `internal/forge` | генериране на Sigma/Suricata/YARA/STIX + инцидентен доклад |
| `internal/assure` | самотест на веригата + **Detectability Score** (fingerprint) |
| `internal/config` | YAML манифест, валидация, `plan` диф, immutable настройки |
| `internal/app` | сглобяването на едно място (бинарът и e2e тестовете ползват него) |
| `internal/presence` | overlay: хъб + Presence Agent, тунел с мултиплексиране, взаимен TLS + собствен CA (`ca.go`) |
| `internal/life` | синтетичен живот: детерминистичен график на логини/логове/lastLogon като функция на времето; примамката изглежда все по-обитаема при всяка проверка |
| `internal/farm` | пълни VM примамки: provisioner, containment gate, baseline, revert, burn, start/stop |
| `internal/drivers/fabric` | `nftables` (налага + чете правилата), `probe` (тества реалната достижимост) |
| `internal/drivers/observer` | `none` (честен no-op) + `drakvuf` (agentless VMI; пълен glue: config→app wiring, domain resolver, DumpMemory, crypto hook, Xen Probe; валидация на хардуер остава) |
| `internal/api` | REST (32 endpoint-а) + вградена конзола (`internal/api/web/` — 12-секционен SPA) |
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
| `cmd/mirage-director`, `cmd/miragectl`, `cmd/mirage-presence`, `cmd/mirage-breadcrumbs` | бинарите. `miragectl` изкарва всичко: doctor/plan/apply/verify/events/forge/tokens/assure/fingerprint/vms/presence-ca/economics + **export/compliance/insider/fleet/graph/toolkit/watermark/replay** |

### Протоколи (`internal/honeyd/svc_*.go`)

`ssh` (истински, x/crypto), `ldap` (фалшива AD), `kerberos` (истински KDC:
enumeration, spraying, AS-REP roast и kerberoast с crackable RC4-HMAC hash),
`smb` (NetNTLMv2 улов), `http`, `telnet`, `ftp` (+ransomware engine), `redis`,
`mysql` (верифицира подхвърлена парола от скрамбъла), `mssql` (възстановява
паролата в чист текст), `vnc`, `smtp`, `snmp` (UDP), `modbus` (ICS), `tokens`
(callback приемник), `generic`.

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
3. ~~**Комерсиален GUI**~~ ✓ — 13-секционен SPA, 34 API endpoint-а.
4. ~~**VMI observer — hypervisor glue**~~ ✓ — пълен glue: config→app wiring,
   domain resolver, Observe горутини, DumpMemory (vmi-dump-memory/xl), crypto
   hook (apimon→T1486), Xen Probe (/proc/xen + xl), API endpoint-и, GUI секция.
   14 теста. **Парсерът е валидиран срещу DRAKVUF v1.1 сорс.**

   **Xen валидация (2026-08-30):** Xen 4.17 инсталиран на Proxmox хоста като
   dual-boot. libvmi компилиран, `vmi-process-list` и `vmi-dump-memory` работят
   срещу HVM domU. DRAKVUF v1.1 компилиран, но **не може да тръгне** — CPU
   (i3-9100T) няма VMFUNC за altp2m. Парсерът е валидиран срещу сорс кода:
   поправени TimeStamp (quoted string), UserId (int вместо UserName), filedelete2.

   **Важно за средата:** DRAKVUF изисква **Xen + CPU с VMFUNC** (altp2m).
   Наличният i3-9100T го няма. VM примамките работят на Proxmox (KVM/QEMU),
   но agentless VMI иска Xen dom0 на CPU с EPT+VMFUNC (Haswell+, не всички).
5. ~~**mirage-vault**~~ ✓ — ed25519 seal на chain head + опционален RFC 3161
   timestamp (`miragectl vault seal|verify`). Веригата вече е проверима от трета
   страна: подписът казва „това е от това внедряване", timestamp-ът — „съществуваше
   тогава". Tamper на файла проваля verify.
6. **Multi-tenancy, SSO/SAML** — за MSSP канала.
7. **Plugin SDK** — gRPC, HashiCorp go-plugin модел.
8. **Допълнителни compute драйвери** — vSphere, Hyper-V (Phase 5).

Отхвърлени съзнателно (виж `docs/11-IDEAS.md`): hack-back, автоматично
блокиране на IP към прод firewall, cloud-only контролер.

---

## 6. Документация

`docs/00`–`docs/11` са планът: визия, архитектура, компоненти, каталог на
измамата, containment/правна рамка, модел на данните, профили на внедряване,
роудмап, стек, бизнес, интеграции, идеи. `docs/adr/` — решенията с обосновка.
