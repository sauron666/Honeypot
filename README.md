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
| Тип примамка | предимно емулирани/контейнерни услуги | **истински пълни OS** (KVM/Proxmox) + емулирана ферма за мащаб |
| Наблюдение | in-guest агент или само лог на услугата | **agentless VMI** (hypervisor introspection) — няма какво да убиеш/намериш |
| Форензика | alert + няколко полета | пълна сесия: PCAP-NG, TLS keys, keystrokes, RDP видео, memory dump, artefact chain |
| Реализъм | празни машини, нови артефакти | **Life Engine** — синтетични потребители, стари timestamps, реален event log, реален browser history |
| Ransomware | alert при първи докоснат файл | FUSE tarpit + **прихващане на симетричния ключ** от паметта + авто-snapshot/revert |
| Identity deception | статични фалшиви акаунти | AD/ADCS honeytokens: kerberoast/AS-REP/DCSync/ESC1 капани, автогенерирани от реалната схема |
| Output | alert към SIEM | **автогенерирани Sigma/YARA/Suricata правила + STIX/MISP** от наблюдаваното поведение |
| Екосистема | заключена във вендора | open SOC stack: Velociraptor, Wazuh/Elastic/Splunk, Suricata, Zeek, TheHive, MISP, OpenCTI |

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

- **Compute:** KVM/libvirt, Proxmox, vSphere, Hyper-V, Nutanix, XCP-ng, AWS/Azure/GCP,
  Kubernetes, Podman — или изобщо без хипервайзор ("honeypot в кутия").
- **Мрежа:** inline (реални VLAN-и), **overlay** (WireGuard, без никаква промяна в
  мрежата) или cloud (SG/NSG).
- **Идентичност:** AD/ADCS, Entra ID, Okta, Google Workspace, FreeIPA, Keycloak.
- **Изход:** всеки SIEM/SOAR/EDR/TI през syslog, ECS, OCSF, CEF, STIX.

Целта е **10 минути до първата примамка** в най-простия профил.

## Бърз старт

Нужен е само Go 1.24+. Без база данни, без Docker, без root.

```bash
make build
./bin/miragectl doctor --config profiles/p0-box.yaml   # проверка преди старт
./bin/mirage-director --config profiles/p0-box.yaml
# конзолата: http://127.0.0.1:8422
```

Това вдига три примамки с последователни идентичности (уеб сървър, база данни,
NAS) на девет порта. Всяко докосване се записва, зашива се в hash chain и се
свързва в engagement.

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
| `internal/drivers/compute` | `inproc`, `podman`, `libvirt` |
| `internal/drivers/fabric` | `nftables` (налага и проверява), `probe` (проверява реалността, не правилата) |
| `internal/farm` | **пълни VM примамки**: provisioner, baseline snapshot, reset след engagement, **burn** (запазва компрометираната машина като доказателство) |
| `internal/drivers/sink` | `stdout`, `file`, `webhook`, `syslog` (RFC 5424), `elastic`, `splunk` |
| `internal/honeyd` | 15 протокола: **ssh** (истински), **ldap** (фалшив AD), **smb** (NetNTLMv2 улов), **http**, **telnet**, **ftp**, **redis**, **mysql**, **mssql**, **vnc**, **smtp**, **snmp** (UDP), **modbus** (ICS), **tokens**, **generic** |
| `internal/honeyd` персони | `linux/web`, `linux/db`, `linux/backup`, `linux/fileserver` (генериран дял с canary файлове), `windows/dc` (фалшива AD с kerberoast/AS-REP/ADCS/LAPS примамки) |
| `internal/tokens` | honeytokens: 8 типа, callback приемник, watcher за подхвърлени стойности, генератор на .docx |
| `internal/forge` | **автогенериране на Sigma / Suricata / YARA / STIX + инцидентен доклад** |
| `internal/assure` | **самотест** (синтетичен атакуващ проверява веригата) + **Detectability Score** (колко разпознаваема е всяка примамка и какво я издава) |
| `internal/ransomware` | **шест независими сигнала за криптор + tarpit + извличане на контактите от бележката** |
| `internal/engagement` | стичване на събития в една история + risk score; възстановяване от evidence файл |
| `internal/alert` | праг по severity, дедупликация, линк към engagement |
| `internal/presence` | **overlay режим**: примамки в чужд сегмент без промяна на мрежата; **взаимен TLS** + собствен CA |
| `internal/api` | REST API + операторска конзола (вграден UI, строг CSP) |
| `cmd/mirage-presence` | Presence Agent — поема свободни адреси и тунелира към хъба |
| `cmd/miragectl` | doctor, **plan**, **apply**, personas, services, drivers, verify, events, tokens, **forge**, **assure**, **fingerprint**, **presence-ca**, **vms**, status |

Тестове: unit за всеки пакет + end-to-end сценарий с пълна атакова верига
(`test/e2e`), всичко под `-race`.

## Какво НЕ работи още

Няма VMI observer. Няма Kerberos KDC (AS-REP и kerberoast се засичат при
изброяването през LDAP, не при самото искане на тикет). Няма Life Engine
(синтетични потребители).

Пълните VM примамки са реализирани откъм платформата — provisioner, containment
gate, baseline, reset, burn — но **самите образи не се доставят**. Профил P4
очаква libvirt шаблони, които вече съществуват на хоста; MIRAGE ги клонира, не
ги строи. Има и `proxmox` драйвер в плана, но още го няма.

SMB покрива negotiate, session setup (с улов на NetNTLMv2) и tree connect;
файловите операции връщат ACCESS_DENIED. Сервирането на файлове по SMB2
изисква валидация срещу истински Windows клиенти, преди да е честно да се
твърди — затова ransomware двигателят засега гледа FTP дяла. Пътната карта и редът на изпълнение: `docs/07-ROADMAP.md`.

## Статус

**Фаза 0 завършена, фаза 1 почти завършена.** Продуктът е използваем днес в профил P0.
