# 02 — Компоненти

> **Бележка за текущото състояние:** този документ е проектен план, писан преди
> имплементацията. Много от описаните компоненти вече са готови, но архитектурата
> се опрости в процеса: **един бинар** (`mirage-director`) вместо микроуслуги,
> in-process шина вместо NATS, JSONL hash chain вместо Postgres/ClickHouse.
>
> **Какво е реализирано и къде:**
>
> | Компонент по план | Реален пакет | Статус |
> |---|---|---|
> | mirage-director | `cmd/mirage-director` + `internal/app` | ✅ |
> | mirage-provisioner | `internal/farm` | ✅ (provisioner + containment + burn) |
> | mirage-observer | `internal/drivers/observer` | ◐ (parsing/mapping; hypervisor-glue остава) |
> | mirage-tap | — | ✗ отложен |
> | mirage-gateway | — | ✗ отложен (containment чрез fabric drivers) |
> | mirage-honeyd | `internal/honeyd` | ✅ (17 протокола, включително kerberos и mcp) |
> | mirage-tokens | `internal/tokens` | ✅ (10 типа + prompt canary) |
> | mirage-breadcrumbs | `internal/breadcrumbs` + `cmd/mirage-breadcrumbs` | ✅ |
> | mirage-brain | `internal/engagement` + `internal/toolkit` | ✅ (stitching + toolkit DB) |
> | mirage-forge | `internal/forge` | ✅ |
> | mirage-presence | `internal/presence` + `cmd/mirage-presence` | ✅ (+ mTLS + CA) |
> | mirage-graph | `internal/graph` | ✅ |
> | mirage-assure | `internal/assure` | ✅ |
> | mirage-life | `internal/life` | ✅ |
> | mirage-jit | `internal/honeyd/jit.go` | ✅ |
> | mirage-watermark | `internal/watermark` | ✅ |
> | mirage-comply | `internal/compliance` | ✅ |
>
> Долу е оригиналният проектен план за справка.

Всеки компонент в плана е отделен процес/бинар. В практиката повечето живеят
в един процес (`mirage-director`); разделянето е по Go пакети, не по бинари.

---

## mirage-director  — control plane
**Отговорност:** единствен източник на истина за конфигурация, инвентар, политики,
кампании, RBAC, лицензи, tenants.

- REST + gRPC API, OpenAPI спецификация, всичко в UI минава оттук.
- **Deception Campaign** обект: набор от decoys + tokens + breadcrumbs + policy,
  с жизнен цикъл (draft → deployed → engaged → burned → retired).
- **Escalation Broker**: решава L1→L3 handoff (виж `01-ARCHITECTURE §3`).
- **Burn tracking**: примамка, която е била компрометирана и после игнорирана от
  същия актьор, се маркира "burned" → авто-ротация с нова идентичност.
- Go, Postgres, embedded NATS клиент.

## mirage-provisioner — жизнен цикъл на примамките
**Отговорност:** създава/клонира/снапшотва/възстановява примамки.

Drivers:
| Driver | Метод | Забележка |
|---|---|---|
| `proxmox` | Proxmox VE API, linked clones от golden templates | първи клас |
| `libvirt` | direct KVM | за standalone нодове |
| `podman` | контейнерни L2 примамки | ферма за мащаб |
| `vsphere`, `hyperv`, `aws/azure` | по-късно | enterprise |

- **Golden template pipeline**: Packer → template (Win Server 2019/2022, Win 10/11,
  Debian 12/13, Ubuntu, OPNsense, fake NAS/appliance) → **Aging Pass** (виж Life Engine).
- **Instant revert**: ZFS/Ceph snapshot; revert < 15s след инцидент.
- **Fleet rotation**: примамките се пресъздават на график с нови идентичности,
  за да не могат да бъдат картографирани.

## mirage-observer — agentless дълбоко наблюдение (★ diferentiator)
**Отговорност:** вижда всичко вътре в примамката, без да е вътре.

- Работи на всеки хипервайзор нод, извън guest-а.
- **VMI** през libvmi/DRAKVUF върху KVM:
  - process create/exit, DLL/модул load, thread injection
  - файлови операции (CreateFile/Write/Rename/Delete), registry (Win)
  - мрежови сокети, изпълнени команди, зареден shellcode
  - **crypto API hooks** — прихващане на симетрични ключове (виж ransomware)
  - memory dump по тригер, YARA scan върху жива памет
- **Linux примамки**: eBPF от хоста през `nsenter`/pidns наблюдение (без агент в
  guest FS) или VMI, според template-а.
- Изход: `mirage.events.host.*` (OCSF Process/File/Registry/Module Activity).
- Тежка част: Rust/C бридж към libvmi, Go обвивка.

## mirage-tap — мрежов запис и реконструкция
**Отговорност:** пълна мрежова истина.

- Пълен **PCAP-NG** на deception VLAN (mirror/SPAN от vSwitch), с per-session индекс
  и retention политика.
- **Suricata** (IDS режим) + **Zeek** (протоколни логове) като вградени двигатели.
- Собствени **reconstructors**:
  - SSH → keystroke timeline + пълен PTY запис (`asciinema`-съвместим)
  - RDP → видео реконструкция на екрана + clipboard + drive redirect файлове
  - SMB → списък на прочетени/писани файлове, копирани бинарки (auto-carve)
  - HTTP(S) → пълни transactions, извлечени payloads
  - WinRM/WMI/DCERPC → изпълнени команди
- **File carving** → всеки трансфериран бинар отива в MinIO + YARA + (опц.) sandbox.

## mirage-gateway — egress broker (★ containment)
**Отговорност:** единствената врата навън. Виж `docs/04`.

- Режими: `airgap` | `sinkhole` (fake internet) | `brokered` (реален интернет с MITM).
- TLS MITM с наш CA (за наблюдение на C2), запис на JA3/JA4/JARM/HASSH.
- **One-way valve**: изходящ scan, brute force, SMTP, DDoS патерни → блокирани,
  алармирани, kill-switch.
- Rate limit + byte budget на примамка. Превишение → auto-isolate.
- DNS sinkhole + `fakenet`-подобни responder-и за пълна изолация.
- **C2 класификатор**: beacon интервал/jitter анализ, известни profile-и
  (Cobalt Strike malleable, Sliver, Havoc, Mythic, Metasploit), config extraction.

## mirage-honeyd — ферма от емулирани услуги (мащаб)
**Отговорност:** стотици IP-та, десетки протоколи, нищожен ресурс.

Протоколи (L1/L2): SSH, Telnet, FTP/SFTP, HTTP(S), SMB, RDP-front, VNC, LDAP,
MSSQL, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker API, Kubernetes API,
Jenkins, GitLab, Exchange/OWA, Citrix, VPN портали (Fortinet/Palo/Cisco стилове),
IPMI/iDRAC/iLO, принтери, IP камери, NAS (Synology/QNAP стил), SNMP,
**OT: Modbus/TCP, S7comm, DNP3, BACnet, EtherNet/IP**.

- Всяка услуга има **content generator** — реалистично съдържание за вертикала на
  клиента (документи, БД схеми, репозитории, конфигурации).
- Не използва публично известни honeypot кодови бази по подразбиране (анти-сигнатура).

## mirage-tokens — honeytokens
**Отговорност:** примамки без инфраструктура, разпръснати навсякъде.

Типове: AWS/Azure/GCP ключове, API токени, DNS токен, canary URL, Office/PDF документ
с remote-load, `.lnk`, QR, SQL ред, Windows folder token, browser saved credential,
ADCS сертификат, Kerberos SPN, MySQL dump, Slack/Git token, clone-site credential trap.

- Callback receiver (публичен endpoint или собствен домейн) → събитие с IP, UA, geo,
  ASN, TLS fingerprint.
- **Token minting API** + масово разпръскване през `mirage-breadcrumbs`/Velociraptor.

## mirage-breadcrumbs — агент за примамки в РЕАЛНАТА мрежа
**Отговорност:** прави така, че реалният endpoint да сочи към honeynet-а.

Плантира и **самообновява**: фалшиви RDP история и `.rdp` файлове, mapped drives,
credential manager записи, `.ssh/config` + known_hosts, KeePass/`.kdbx` капани,
browser saved passwords, `.aws/credentials`, PowerShell history, scheduled task,
hosts записи, cached AD креденшъли, fake VPN профили.

- Go, Windows/Linux/macOS, tamper-evident, минимален footprint, подписан.
- Алтернативна доставка: **Velociraptor artifact** (за среди, които не искат нов агент).

## mirage-brain — корелация и разказ
**Отговорност:** превръща 10^6 събития в една история.

- **Session stitching**: свързва мрежова сесия + host събития + egress + tokens в
  един `Engagement` обект.
- **ATT&CK mapping** (автоматично, правило-базирано + LLM-подпомогнато ревю).
- **Actor fingerprinting**: JA4+, HASSH, typing cadence, реда на командите, tool hashes,
  езикови артефакти, часова зона на активност → клъстеризация на актьори между инциденти.
- Risk score, kill-chain позиция, прогноза за следваща стъпка.
- Опционален LLM слой (локален, напр. self-hosted) за резюме на инцидента —
  **никога не е в решаващия път за alerting**.

## mirage-forge — генератор на детекции (★ diferentiator)
**Отговорност:** honeypot-ът пише детекциите за реалната мрежа.

От наблюдавана сесия автоматично произвежда:
- **Sigma** правила (process, network, registry) с валидация срещу телеметрията
- **YARA** правила от заловени sample-и
- **Suricata/Snort** сигнатури от C2 трафика (с MITM ключовете)
- **IOC/STIX 2.1** bundle → MISP / OpenCTI
- **Velociraptor hunt** artifact за проверка "имало ли е това в реалната мрежа"
- **Атомарен тест** (Atomic Red Team формат) за валидиране на детекцията

## mirage-vault — форензична цялост
- WORM (write-once) съхранение на артефакти; Merkle hash chain на всички събития.
- Опционален RFC3161 timestamp от външен TSA.
- **Evidence package** експорт: подписан ZIP с pcap, логове, sample-и, memory dump,
  timeline, хешове и chain-of-custody документ — годен за правна употреба.

## mirage-ui
- React/TypeScript. Ключови изгледи:
  - **Live Attacker Cam** — реален timeline на активна сесия + терминален/RDP replay
  - **Engagement timeline** — kill chain с всички артефакти по стъпки
  - **Topology map** — реални + примамени хостове, покритие по VLAN
  - **Deception Coverage Score** — измерима метрика по сегмент и по ATT&CK техника
  - **Evidence locker**, **Token manager**, **Campaign builder**, **Rule forge**

## mirage-life — Life Engine (★ diferentiator за реализъм)
**Отговорност:** примамката да изглежда обитавана.

- **Aging pass** при създаване: файлови timestamps разпръснати през години, реалистичен
  MFT/journal, browser history, prefetch, event log с месеци история, инсталиран
  правдоподобен софтуер, домейн-присъединена машина с реални GPO следи.
- **Синтетични потребители**: headless агенти (от хипервайзора, през console/RDP)
  които логват, отварят файлове, пращат вътрешна поща, печатат, сърфират интранет →
  генерират реални 4624/4768/4776 събития и реален мрежов шум.
- **Съдържание по вертикал**: финанси / здравеопазване / производство / публичен сектор —
  генерирани документи, БД схеми, имена по местна конвенция (напр. кирилица за BG клиент).

---

# Допълнителни компоненти (от разширения каталог идеи, `docs/11-IDEAS.md`)

## mirage-presence — Presence Agent (overlay режим) ★
**Отговорност:** примамки в чужд сегмент, без да се пипа мрежата.

- Малък бинар/контейнер в целевия сегмент. Поема неизползвани IP-та (ARP/NDP responder,
  с проверка за конфликт преди заемане).
- Тунелира трафика през WireGuard към централните примамки (L1 ферма или L3 VM).
- Не съдържа креденшъли към control plane отвъд собствения си ключ; тунелът е
  еднопосочно инициируем, с allowlist на портове и kill switch.
- Дава на MSSP възможност да внедри deception при клиент за 10 минути.

## mirage-graph — Attack Path Deception ★
**Отговорност:** казва **къде** да сложим примамките.

- Пасивно строи граф: AD връзки (read-only, BloodHound-подобно), мрежова достижимост
  (Zeek/NetFlow/firewall правила), cloud IAM, административни пътища.
- Изчислява най-късите пътища от типичен компрометиран endpoint до коронните бижута.
- Предлага (и с одобрение прилага) примамки и breadcrumbs по критичните ребра.
- Метрика: % от пътищата, които пресичат примамка, и на коя средна стъпка.

## mirage-assure — Fingerprint & Deception Assurance ★
Две функции, един компонент — непрекъснато тестване на самите нас.

1. **Fingerprint Assurance**: атакува нашите примамки с известните техники за
   разпознаване на honeypot (Nmap NSE, timing, virtualization checks, липса на
   потребителска активност, сравнение с корпус реални отговори) → **Detectability
   Score** + конкретен списък поправки. Работи и като CI gate.
2. **Deception Assurance**: синтетичен атакуващ изпълнява безобидни сценарии
   (Atomic Red Team стил) и проверява цялата верига — събитие → корелация → alert →
   приет от SIEM. Мълчаливата примамка е по-опасна от липсващата.

## mirage-jit — Just-in-Time примамки
Наблюдава интереса на атакуващия и **създава** релевантната примамка в реално време
(търси MSSQL → появява се MSSQL; търси backup → появява се backup сървър).
Вариация в закъснението, за да не изглежда неестествено. Работи заедно с
Escalation Broker-а и с `mirage-brain` (предсказване на следваща стъпка).

## mirage-cloud — cloud и SaaS deception
- Cloud примамки: fake S3/blob, honey IAM role, honey RDS/Lambda URL, honey K8s API.
- SaaS/IdP: honey потребители в Entra ID/Okta/Workspace, honey OAuth приложение,
  honey Slack/Teams канал, honey SharePoint документи.
- Детекция често **без никаква инфраструктура** — само от audit логовете на доставчика.

## mirage-supply — supply-chain и DevOps deception
Dependency-confusion канари (вътрешни имена на пакети, регистрирани публично като
празни канарчета), honey CI runner, honey repo с "тайни", honey artifact registry,
honey Kubernetes namespace/ServiceAccount/secret.

## mirage-ai — deception за AI агенти ★
Нова повърхност: honey MCP сървър, prompt-injection канари в документи (засичат както
вражески агент, така и shadow AI употреба), honey LLM API ключове, маркиран honey
RAG корпус, agent-in-the-middle примамка за автоматизирани атакуващи агенти.

## mirage-mail — email/BEC deception
Honey мейлбокси, съзнателно "изтекли" в публични корпуси; фалшива финансова
идентичност на сайта, към която отиват BEC опитите; автоматично извличане на
инфраструктурата на кампанията и IOC към mail gateway-а.

## mirage-watermark — воден знак и проследяване на изтичане
Всеки генериран примамен документ носи уникален невидим воден знак (zero-width
символи, микро вариации в оформлението, стеганография). При изтичане знаем кой
канал го е дал и можем да докажем, че документът е фалшив.

## mirage-comply — доказателства за съответствие
Картографира телеметрията към NIS2 (чл. 21), DORA, ISO 27001:2022 (A.8.16, A.5.7),
PCI DSS 4.0 (11.5), SOC 2 (CC7.2), IEC 62443 → генерира PDF доказателствен пакет
за одитор. Евтина функция с пряко влияние върху продажбите в регулирани сектори.

## mirage-range — режим "полигон"
Възпроизвежда записани engagement-и срещу обучаеми; дава на червения екип обективен
запис на собствената им работа. Втори приходен поток върху същия код.

## Разширения на съществуващи компоненти
| Компонент | Добавка |
|---|---|
| `mirage-brain` | Attacker Toolkit DB (отпечатъци на nmap/Impacket/CS/Sliver/Havoc), предсказване на следваща стъпка, Engagement Economics (откраднато атакуващо време) |
| `mirage-director` | Deception-as-Code engine (`plan/apply/destroy`), drift detection, persona registry |
| `mirage-gateway` | tarpit-и и cognitive friction (TCP tarpit, web лабиринт) — само входящо, нула изходящи действия |
| `mirage-life` | персони по вертикал/държава/език от общностния каталог |
| `mirage-forge` | локален LLM аналитик (офлайн, извън решаващия път), чернова на инцидентен доклад |
