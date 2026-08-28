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
| `internal/drivers/sink` | `stdout`, `file`, `webhook`, `syslog` (RFC 5424) |
| `internal/honeyd` | 12 протокола: **ssh** (истински), **http**, **telnet**, **ftp**, **redis**, **mysql**, **mssql**, **vnc**, **smtp**, **snmp** (UDP), **modbus** (ICS), **generic** |
| `internal/honeyd` персони | `linux/web`, `linux/db`, `linux/backup` с виртуална ФС и подхвърлени тайни |
| `internal/tokens` | honeytokens: 8 типа, callback приемник, watcher за подхвърлени стойности, генератор на .docx |
| `internal/forge` | **автогенериране на Sigma / Suricata / YARA / STIX + инцидентен доклад** |
| `internal/engagement` | стичване на събития в една история + risk score; възстановяване от evidence файл |
| `internal/alert` | праг по severity, дедупликация, линк към engagement |
| `internal/api` | REST API + операторска конзола (вграден UI, строг CSP) |
| `cmd/miragectl` | doctor, personas, services, drivers, verify, events, tokens, **forge**, status |

Тестове: unit за всеки пакет + end-to-end сценарий с пълна атакова верига
(`test/e2e`), всичко под `-race`.

## Какво НЕ работи още

Няма VMI observer, няма пълни VM примамки, няма SMB, няма identity/AD deception,
няма ransomware engine, няма Life Engine (синтетични потребители), няма overlay
режим. Пътната карта и редът на изпълнение: `docs/07-ROADMAP.md`.

## Статус

**Фаза 0 завършена, фаза 1 почти завършена.** Продуктът е използваем днес в профил P0.
