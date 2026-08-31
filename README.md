# MIRAGE — Deception & Adversary Observation Platform

> Работно кодово име: **MIRAGE** (Modular Isolated Reconnaissance & Adversary Graph Engine).
> Финалното име се избира преди go-to-market (виж `docs/09-BUSINESS.md`).

MIRAGE е платформа за **active defense / deception**: изолирана honeynet среда, която
изглежда и се държи като реална корпоративна мрежа, примамва атакуващия в себе си и
записва **всичко** — до ниво syscall, файлова операция, натиснат клавиш и мрежов пакет —
без агент в примамката и без атакуващият да може да я разпознае.

## Какво прави различно от FortiDeceptor / Attivo / Acalvio / TrapX / Canary

| Способност | Commercial deception (типично) | MIRAGE |
|---|---|---|
| Тип примамка | предимно емулирани/контейнерни услуги | **истински пълни OS** (KVM/Proxmox, vSphere/Hyper-V експериментално) + емулирана ферма за мащаб |
| Наблюдение | in-guest агент или само лог на услугата | **agentless VMI** на Xen (нищо в госта) **+ in-guest сензор на всеки хипервайзор** (Sysmon/auditd — стандартна телеметрия, не tell) |
| Форензика | alert + няколко полета | пълна сесия: **keystroke replay** (asciinema), memory dump (VMI), append-only artefact chain, **ed25519 seal + RFC 3161 timestamp** (съдебно проверимо). *PCAP-NG/TLS keys/RDP видео — планирани.* |
| Реализъм | празни машини, нови артефакти | **Life Engine** — синтетични логини, стари timestamps, реален auth.log/lastLogon, детерминистичен (без горутина) |
| Ransomware | alert при първи докоснат файл | **hypervisor-agnostic FUSE tarpit + snapshot-on-confirm** (всеки хипервайзор) + crypto-hook на ключа (Xen VMI). Потвърждение за 2-3 операции. |
| Identity deception | статични фалшиви акаунти | AD honeytokens: kerberoast/AS-REP с **crackable hash**, ADCS/LAPS капани; автогенерирани, LDAP и Kerberos четат един каталог |
| Output | alert към SIEM | **автогенерирани Sigma/Suricata/YARA + STIX/TheHive/IOC** от наблюдаваното поведение |
| Съответствие | — | одит срещу **NIS2/DORA/ISO 27001/PCI/SOC2/IEC 62443**; способност→контрол |
| Екосистема | заключена във вендора | 8 драйверни интерфейса (ADR-008); всеки SIEM/SOAR през syslog/ECS/OCSF/STIX |

## Документация

| Док | Съдържание |
|---|---|
| `docs/00-VISION.md` | Цел, потребители, конкурентен анализ, принципи |
| `docs/01-ARCHITECTURE.md` | Планове (control/data/sensor/observation), диаграми, потоци |
| `docs/02-COMPONENTS.md` | Всеки компонент: отговорност, вход/изход, технологии |
| `docs/03-DECEPTION-CATALOG.md` | Каталог на примамки, honeytokens, breadcrumbs, anti-fingerprinting |
| `docs/04-ISOLATION-SAFETY.md` | Containment модел, kill-switch, правни и етични рамки |
| `docs/05-DATA-MODEL.md` | Схема на събитията (OCSF), storage, chain of custody |
| `docs/06-DEPLOYMENT-PROFILES.md` | Седем профила на внедряване: SMB, mid-market, enterprise, MSSP, cloud, OT/air-gap, range |
| `docs/07-ROADMAP.md` | Фази, deliverables, оценки, критерии за приемане |
| `docs/08-TECH-STACK.md` | Езици, библиотеки, repo layout, build/CI |
| `docs/09-BUSINESS.md` | Лицензиране, open-core, ценообразуване, пазар |
| `docs/10-INTEGRATIONS.md` | Драйверни абстракции, матрица на поддръжката, plugin SDK, overlay режим |
| `docs/11-IDEAS.md` | Разширен каталог идеи с оценка и приоритет |

## Универсалност

MIRAGE не е обвързан с конкретна инфраструктура. Ядрото говори с външния свят само
през осем драйверни интерфейса (`docs/10-INTEGRATIONS.md`), а начинът на внедряване
се избира от профил (`docs/06-DEPLOYMENT-PROFILES.md`):

- **Compute (реализирани):** `inproc` ("honeypot в кутия"), `podman`, `libvirt`/KVM,
  `proxmox` (field-proven на PVE 8.4), `vsphere` и `hyperv` (experimental — чакат
  жива валидация). *Планирани:* Nutanix, XCP-ng, AWS/Azure/GCP, Kubernetes.
- **Наблюдение:** `drakvuf` (agentless VMI, Xen) и `agent` (in-guest сензор, всеки
  хипервайзор). Ransomware trap-ът работи навсякъде независимо от compute драйвера.
- **Мрежа:** inline (реални VLAN-и през `nftables`), **overlay** (собствен mTLS тунел,
  без никаква промяна в мрежата), `freeradius` NAC (CoA към deception VLAN).
- **Идентичност (реализирано):** фалшива AD (LDAP + истински KDC). *Планирани:*
  Entra ID, Okta, Google Workspace, FreeIPA, Keycloak.
- **Изход:** всеки SIEM/SOAR/TI през `stdout`/`file`/`webhook`/`syslog`/`elastic`/`splunk`
  + STIX/TheHive/IOC износ.

Целта е **10 минути до първата примамка** в най-простия профил.

## Бърз старт

Нужен е само Go 1.24+. Без база данни, без Docker, без root.

```bash
make build
./bin/miragectl doctor --config profiles/p0-box.yaml   # проверка преди старт
./bin/mirage-director --config profiles/p0-box.yaml
# конзолата: http://127.0.0.1:8422
```

Това вдига шест примамки с последователни идентичности (уеб сървър, база данни,
NAS, файлов сървър, домейн контролер, PLC) на 22 порта. Всяко докосване се
записва, зашива се в hash chain и се свързва в engagement.

Пробвай го срещу самия него:

```bash
curl http://127.0.0.1:8080/.env                       # scanner path
ssh -p 2222 root@127.0.0.1                            # паролата "toor" минава
redis-cli -p 6380 CONFIG SET dir /var/spool/cron      # класическата Redis верига
mysql -h 127.0.0.1 -P 3307 -u dba -pdba123            # подхвърлената парола минава
./bin/miragectl verify --file data/evidence.jsonl     # доказателствата непокътнати?
```

Deception-as-Code — виж какво ще се промени, преди да се промени, и приложи
без рестарт (рестартът е видим за атакуващ, който вече е вътре):

```bash
./bin/miragectl plan  --config profiles/p0-box.yaml
./bin/miragectl apply --config profiles/p0-box.yaml
```

Провери, че платформата наистина детектира (мълчалива примамка е по-опасна
от липсваща):

```bash
./bin/miragectl assure           # атакува собствените примамки и проверява веригата
./bin/miragectl fingerprint -v   # колко разпознаваеми са примамките и какво ги издава
```

Всеки deception продукт твърди, че примамките му са неразличими. Никой не
публикува число. `fingerprint` дава число за всяка примамка, конкретното нещо,
което я издава, и какво да се направи по въпроса.

Синтетичен живот. Статична примамка се издава с времето: атакуващ, който вдигне
„натоварен" сървър, пусне `last` два пъти през десет минути и види един и същ
последен логин, разбира, че машината е декор. `internal/life` прави примамката
да изглежда обитаема — и все по-обитаема при всяка проверка — но **без нито една
фонова горутина**. Животът е чиста функция на времето: от seed-а и текущия миг
се изчислява какво „би се случило" дотогава — детерминистичен, човешки оформен
график от логини, cron и файлове. `last`, `w`, `/var/log/auth.log` и
`lastLogonTimestamp` се рендерират от него, така че историята е последователна
(логин в `last` има съответстващ ред в auth.log в същата секунда) и напредва.
Нищо не се мутира, нищо не се емитира — синтетичната активност никога не влиза
в доказателствената верига като атакуващ.

Истински KDC. LDAP примамката вижда, че някой *търси* roastable акаунти;
KDC-то вижда как отива и ги *взема* — а много инструменти прескачат LDAP
(kerbrute, Rubeus с списък имена, `GetNPUsers -usersfile`). Три неща, които
LDAP-само наблюдение не дава:

- **Изброяване на потребители** — KDC отговаря различно на съществуващ и на
  несъществуващ принципал, всеки опитан е записан по ред; това е речникът на
  атакуващия, който често го издава по-добре от IP-то.
- **Password spray** — pre-authentication носи криптиран timestamp; KDC-то го
  дешифрира, така че грешна парола се различава от малформиран пакет, а една
  парола срещу двайсет акаунта — от двайсет пароли срещу един.
- **Roast, който наистина се чупи** — раздаденият blob е истински RC4-HMAC над
  истински DER, с NT hash на планирана парола; hashcat (режими 18200/13100) я
  намира. Паролата отключва нищо — но watcher-ът я чака навсякъде другаде, така
  че в мига, в който атакуващият я пробва по SSH/SMB/MSSQL, офлайн кракът се
  свързва с онлайн опита в един engagement.

Overlay режим — примамки в чужд сегмент без нито една промяна по мрежата.
Агентът поема свободни адреси там, където е, и тунелира всичко до хъба; VLAN,
маршрути и firewall правила остават каквито са. Тунелът е с **взаимен TLS**,
а материалът се издава от самия MIRAGE, защото функция, която изисква отделен
PKI проект, преди да тръгне, е функция, която остава изключена:

```bash
./bin/miragectl presence-ca -dir ./presence-pki \
    -hosts mirage-hub.example.net -agents acme-floor-3

# на хъба: presence.tls.{cert_file,key_file,ca_file} в профила
# в чуждия сегмент (агентът получава само ca.crt и своята двойка):
MIRAGE_PRESENCE_TOKEN=... ./bin/mirage-presence \
    -hub mirage-hub.example.net:8443 -id acme-floor-3 \
    -addresses 10.20.30.41 -services ssh:22,smb:445 \
    -tls-cert agent-acme-floor-3.crt -tls-key agent-acme-floor-3.key -tls-ca ca.crt
```

С `ca_file` на хъба агент без сертификат се отрязва, преди изобщо да подаде
токен: токен, прочетен от компрометиран агент, не стига, за да проектира някой
свои примамки. `ca.key` не напуска хъба.

Пълни VM примамки (профил P4) — истински машини, не емулация. Затова и въпросът
за изолацията тук не е чекбокс: примамка, която атакуващият превземе, е истински
хост в мрежата. Нищо не тръгва, преди containment да е **проверен**, а не приет:

```bash
./bin/miragectl doctor --config profiles/p4-fullvm.yaml   # проверява и живите правила
./bin/miragectl vms                                       # какво върви и какво е изгорено
./bin/miragectl vms -burn vm-fs01 -reason "root чрез sudo CVE"
```

`burn` спира примамката, изолира я (ако fabric драйверът може) и **никога** не я
връща в строя: тя вече е доказателството. `revert` връща примамката към чистия
baseline, но първо снимка на мръсното състояние — reset, който трие каквото
атакуващият е инсталирал, превръща пробива в анекдот.

Два fabric драйвера, защото отговарят на различни въпроси: `nftables` чете и
пише намерението (правилата), `probe` проверява реалността (какво наистина
стига пакет от примамката). Внедряване, в което двете не съвпадат, е точно това,
което превръща honeypot-а в плацдарм.

И най-важното — примамката пише детекциите за реалната мрежа:

```bash
./bin/miragectl forge --file data/evidence.jsonl --out ./detections
# report.md, sigma-*.yml, suricata-*.rules, captured-*.yar, stix-*.json, iocs-*.tsv
```

## Какво работи днес

| Компонент | Състояние |
|---|---|
| `internal/event` | OCSF схема, ULID, канонична сериализация, **append-only hash chain** |
| `internal/store` | append-only evidence файл, възстановяване след рестарт, стриймваща проверка |
| `internal/bus` | шина със subject matching; бавен consumer не блокира примамка |
| `internal/drivers` | осемте абстракции + registry с capabilities (ADR-008) |
| `internal/drivers/compute` | `inproc`, `podman`, `libvirt`, **`proxmox`** (REST+pvesh, field-proven PVE 8.4), **`vsphere`** и **`hyperv`** (experimental) |
| `internal/drivers/fabric` | `nftables` (налага и проверява), `probe` (проверява реалността, не правилата) |
| `internal/drivers/observer` | `none` + **`drakvuf`** (agentless VMI, Xen — **живо валидиран на Windows Server 2025 и Linux**) + **`agent`** (in-guest сензор, всеки хипервайзор) |
| `internal/drivers/nac` | `none` + **`freeradius`** (RADIUS CoA — насочва непознато устройство към deception VLAN) |
| `internal/farm` | **пълни VM примамки**: provisioner, baseline snapshot, reset след engagement, start/stop, **burn** (запазва компрометираната машина като доказателство) |
| `internal/fusetrap` | **hypervisor-agnostic ransomware trap**: FUSE bait дял → детектор + tarpit + snapshot-on-confirm (всеки хипервайзор) |
| `internal/catalog` | **библиотека с образи**: внасяне на ISO/OVA/OVF/qcow2/vmdk, difficulty tiers, саниране (маха CTF флагове, ресетва креденшъли, watermark) |
| `internal/drivers/sink` | `stdout`, `file`, `webhook`, `syslog` (RFC 5424), `elastic`, `splunk` |
| `internal/honeyd` | 17 протокола: **ssh** (истински), **ldap** (фалшив AD), **kerberos** (истински KDC: AS-REP/kerberoast с crackable hash), **smb** (NetNTLMv2 улов), **http**, **telnet**, **ftp**, **redis**, **mysql**, **mssql**, **vnc**, **smtp**, **snmp** (UDP), **modbus** (ICS), **mcp** (honey MCP/AI сървър), **tokens**, **generic** |
| `internal/honeyd` персони | `linux/web`, `linux/db`, `linux/backup`, `linux/fileserver` (генериран дял с canary файлове), `windows/dc` (фалшива AD с kerberoast/AS-REP/ADCS/LAPS примамки) |
| `internal/tokens` | honeytokens: 8 типа, callback приемник, watcher за подхвърлени стойности, генератор на .docx |
| `internal/forge` | **автогенериране на Sigma / Suricata / YARA / STIX + инцидентен доклад** |
| `internal/assure` | **самотест** (синтетичен атакуващ проверява веригата) + **Detectability Score** (колко разпознаваема е всяка примамка и какво я издава) |
| `internal/ransomware` | **шест независими сигнала за криптор + tarpit + извличане на контактите от бележката** |
| `internal/engagement` | стичване на събития в една история + risk score; възстановяване от evidence файл |
| `internal/alert` | праг по severity, дедупликация, линк към engagement |
| `internal/presence` | **overlay режим**: примамки в чужд сегмент без промяна на мрежата; **взаимен TLS** + собствен CA |
| `internal/life` | **синтетичен живот**: логини, логове и lastLogon, които напредват във времето — примамката изглежда обитаема и все по-обитаема при всяка проверка |
| `internal/compliance` | одит срещу **NIS2/DORA/ISO 27001/PCI/SOC2/IEC 62443**; способност→контрол, markdown доклад |
| `internal/export` | STIX 2.1 bundle, TheHive alert, дедупликиран IOC списък |
| `internal/vault` | **ed25519 seal на chain head + RFC 3161 timestamp** — веригата е проверима от трета страна |
| `internal/graph`, `internal/toolkit`, `internal/insider`, `internal/watermark`, `internal/fleet`, `internal/replay` | attack-path deception, attacker toolkit DB, insider-threat kit, watermarking, авто-ротация на идентичности, SSH session replay (asciinema) |
| `internal/packs` | **Deception Packs** — подписани, версионирани пакети с измама (персони/декои/токени); дистрибуционната машина (Sigma/Atomic Red Team модел) |
| `internal/saasid`, `internal/bec` | **identity/BEC deception** — honey Entra/Okta акаунти + audit-log matcher; honey финанс идентичности + анализ на BEC кампания |
| `internal/analyst`, `internal/feed`, `internal/wireless` | **LLM аналитик** (офлайн/локален, извън alerting), **анонимизиран global feed** (подписан TTP feed), **BYOD deception** (honey mDNS/DNS-SD + recon детектор) |
| `internal/api` | **REST API (39 endpoint-а) + операторска конзола (17-секционен SPA, строг CSP, textContent-only)** |
| `cmd/mirage-presence` | Presence Agent — поема свободни адреси и тунелира към хъба |
| `cmd/mirage-breadcrumbs` | **Breadcrumbs агент** — подхвърля следи на реален endpoint (.rdp, ~/.aws, ssh config, история), които водят право в honeynet-а; всяка следа носи honeytoken |
| `cmd/mirage-sensor` | **in-guest колектор** — Linux netlink process connector / Windows Sysmon → agent observer (всяка команда вътре в full-OS декой на всеки хипервайзор) |
| `cmd/miragectl` | doctor, **plan**, **apply**, personas, services, drivers, verify, events, tokens, **forge**, **assure**, **fingerprint**, **presence-ca**, **vms**(+**smoketest**), **images**, economics, **export**, **compliance**, **insider**, **fleet**, **graph**, **toolkit**, **watermark**, **replay**, **vault**, status |

Тестове: unit за всеки пакет + end-to-end сценарий с пълна атакова верига
(`test/e2e`), всичко под `-race`.

## Какво НЕ работи още (честно)

- **agentless VMI е заключен за Xen + VMFUNC CPU.** DRAKVUF glue-ът е готов и
  **живо валидиран** (Windows Server 2025, Linux), но иска Xen dom0 на CPU с
  altp2m (Ice Lake+; Coffee/Comet Lake го нямат). На KVM/VMware/Hyper-V пълната
  видимост идва от **in-guest сензора** (`agent`), не от VMI. KVM-VMI (KVMi) иска
  пачнат хост — lab-tier, не се доставя.
- **`vsphere` и `hyperv` драйверите са experimental** — unit-тествани срещу
  синтетични отговори, чакат жива валидация (`miragectl vms smoketest`). Proxmox
  и libvirt/KVM са проверени.
- **Ransomware детекторът** се храни от FTP дяла и **FUSE trap-а** (hypervisor-
  agnostic). SMB2 вече сервира файлове (create/read/write/dir + NetNTLMv2 улов),
  но записите по SMB се записват, не се скорират — детекцията е през trap-а.
- **Не са реализирани:** PCAP-NG / TLS session keys / RDP видео запис; cloud compute
  драйвери (AWS/Azure/GCP), Kubernetes, Nutanix, XCP-ng; не-AD идентичност (Entra/
  Okta/…); multi-tenancy / SSO-SAML; Plugin SDK (gRPC). Виж `docs/07-ROADMAP.md`.
- **Образите не се дистрибутират** — библиотеката ги внася по път и ги санира;
  ти доставяш образа (HTB/собствен). Има cloud-init Ubuntu 24.04 шаблон.

## Статус

**Фаза 0 и 1 завършени; продуктът е използваем и продаваем днес в профил P0**
(в кутия + емулирани + ransomware trap + in-guest сензор), с Proxmox за пълни VM
примамки. Остават хардуерни валидации (Xen dom0, vsphere/hyperv на жив хост).
~46 600 реда Go, 438 тестови функции, целият сюит зелен под `-race`.
