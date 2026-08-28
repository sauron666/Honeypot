# 02 — Компоненти

Всеки компонент е отделен процес/бинар. Комуникация: gRPC (control) + NATS (data).

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
