# 10 — Абстракции, драйвери и интеграции

> Принцип: **в ядрото няма нито един вендор.** Всяко докосване до външен свят минава
> през интерфейс. Proxmox, OPNsense, FreeRADIUS, Velociraptor са *драйвери*, не
> архитектура. Това е разликата между "нашата лаборатория" и "продукт".
>
> **Реализирани драйвери** (към последния commit): Compute: `inproc`, `podman`,
> `libvirt`, `proxmox` (field-proven PVE 8.4), `vsphere` и `hyperv` (experimental) |
> Fabric: `nftables`, `probe` | Observer: `none`, `drakvuf` (agentless VMI, живо
> валидиран), `agent` (in-guest сензор) | NAC: `none`, `freeradius` (RADIUS CoA) |
> Sink: `stdout`, `file`, `webhook`, `syslog`, `elastic`, `splunk`. Identity,
> Forensics, Intel категориите имат интерфейси, но не и имплементации (Intel се
> покрива функционално от `internal/export` — STIX/TheHive/IOC).
> Таблиците по-долу са **проектен план** — ● означава "планиран първи клас", не
> "реализиран"; виж `miragectl drivers` за живия списък.

## 1. Осемте абстракции

```go
// internal/drivers — всеки интерфейс има поне: NoopDriver (за тестове),
// един OSS референтен драйвер и capability decl. (какво умее конкретният драйвер)

type ComputeDriver   interface { /* Clone, Start, Stop, Snapshot, Revert, Destroy, Console */ }
type FabricDriver    interface { /* Segments, ACL, Mirror, Route, Isolate, KillSwitch */ }
type NACDriver       interface { /* OnUnknownDevice → AssignSegment, Quarantine */ }
type IdentityDriver  interface { /* ReadSchema, CreateHoneyPrincipal, IssueCert, WatchAuth */ }
type ObserverDriver  interface { /* Attach, TraceProcess/File/Registry, DumpMemory */ }
type ForensicsDriver interface { /* Deploy, Collect, Hunt, Verify */ }
type SinkDriver      interface { /* Alert, Event, Bulk — SIEM/SOAR/ticket/chat */ }
type IntelDriver     interface { /* Enrich, Publish — TI платформи */ }
```

Правило: **компонент, който импортира конкретен вендорски пакет извън
`internal/drivers/<vendor>/`, не минава ревю.**

## 2. Матрица на поддръжката

Легенда: ● първи клас · ○ планиран · ◌ общност/best-effort

### ComputeDriver — къде живеят примамките
| Драйвер | Статус | Ниво на примамка | Забележка |
|---|---|---|---|
| libvirt/KVM | ● | L0–L4 | референтна имплементация; agentless VMI иска Xen/KVMi → иначе in-guest `agent` |
| Proxmox VE | ● **field-proven (PVE 8.4)** | L0–L4 | API token, linked clones, snapshots; наблюдение през in-guest `agent` + ransomware trap |
| Podman/Docker | ● | L0–L2 | ферма за мащаб, без VMI |
| VMware vSphere | ◐ **experimental** | L0–L3 | vCenter REST, adopt-first; наблюдение през in-guest `agent` |
| Hyper-V / SCVMM | ◐ **experimental** | L0–L3 | PowerShell/SSH, adopt-first; наблюдение през in-guest `agent` |
| Nutanix AHV | ○ | L0–L3 | AHV е KVM → VMI е възможно |
| XCP-ng / Xen | ○ | L0–L4 | Xen е роден за libvmi — потенциално най-добър VMI |
| AWS EC2 / Azure / GCP | ○ ф.6 | L0–L3 | ephemeral decoys, без VMI → eBPF/агент fallback |
| Kubernetes | ○ ф.6 | L0–L2 | honey namespace, honey ServiceAccount |
| Bare metal (PXE) | ◌ | L0–L4 | за OT и за максимален реализъм |
| **Nested/none** | ● ф.1 | L0–L2 | "honeypot в кутия" — един бинар, без хипервайзор |

### FabricDriver — сегментация, mirror, изолация
| Драйвер | Статус | Умее |
|---|---|---|
| Linux bridge / nftables (вграден) | ● ф.0 | segments, ACL, mirror (tc), kill switch |
| Open vSwitch | ● ф.1 | + VXLAN, per-port mirror, QoS |
| OPNsense / pfSense | ● ф.1 | API: VLAN, правила, NAT, Suricata |
| VyOS / RouterOS | ○ | ACL, VLAN |
| Cisco (IOS/NX-OS), Juniper, Arista | ○ ф.5 | NETCONF/RESTCONF |
| Fortinet / Palo Alto / Check Point | ○ ф.5 | API правила + tag-базирана изолация |
| Cloud SG/NSG/VPC | ○ ф.6 | security groups, flow logs, TGW mirror |
| **Overlay режим (WireGuard mesh)** | ● ф.2 | ★ примамки без промяна на мрежата — виж §4 |

### NACDriver — пренасочване на непознати устройства
| Драйвер | Статус |
|---|---|
| FreeRADIUS | ● ф.4 |
| PacketFence | ○ |
| Cisco ISE | ○ ф.5 |
| Aruba ClearPass | ○ ф.5 |
| Generic RADIUS (CoA / RFC 5176) | ● ф.4 |

### IdentityDriver — identity deception
| Драйвер | Статус | Умее |
|---|---|---|
| Active Directory (LDAP/ADSI) | ● ф.3 | honey principals, SPN, AS-REP, DCSync canary |
| AD CS | ● ф.3 | honey шаблони, token сертификати |
| Entra ID / Azure AD | ○ ф.5 | honey users, OAuth app canary, CA policy canary |
| Okta / JumpCloud / Google Workspace | ○ ф.5 | honey акаунти, API token canary |
| FreeIPA / OpenLDAP / Keycloak | ○ | Linux-центрични среди |
| HashiCorp Vault | ○ | honey secret path с audit tripwire |

### ObserverDriver — дълбоко наблюдение
| Драйвер | Статус | Дълбочина | Следа в госта |
|---|---|---|---|
| libvmi/DRAKVUF (**само Xen** + VMFUNC CPU) | ● **живо валидиран** (Win Server 2025, Linux) | процеси, файлове, регистри, crypto hook, memory dump | **нула** |
| Мрежова реконструкция (емулирани услуги) | ● | команди, keystroke replay (asciinema) | нула |
| **In-guest `agent` сензор** (всеки хипервайзор) | ● **реализиран** (`mirage-sensor`: Linux netlink, Windows Sysmon) | процеси/команди/файлове | видима — стандартна телеметрия (Sysmon/auditd), не tell |
| Ephemeral snapshot forensics | ○ ф.5 | post-hoc | нула — snapshot + офлайн анализ |

### ForensicsDriver / SinkDriver / IntelDriver
| Категория | Драйвери |
|---|---|
| Forensics/EDR | Velociraptor ●, GRR ○, Wazuh ●, osquery ○, Defender/S1/CrowdStrike API ○ |
| SIEM | syslog RFC5424 ●, webhook ●, Elastic/ECS ●, Splunk HEC ●, Sentinel ○, QRadar ○, Chronicle ○, OpenSearch ● |
| SOAR/Ticket | TheHive/Cortex ●, Shuffle ●, Tines ○, Jira/ServiceNow ○, PagerDuty ○ |
| Chat | Slack ●, Teams ●, Telegram ●, Matrix ○, Discord ◌ |
| Intel | MISP ●, OpenCTI ●, STIX2.1 ●, VirusTotal ○, YARAify ○ |

## 3. Plugin SDK
За всичко извън първия клас — външни plugin-и, без форк на ядрото.

- **Транспорт:** gRPC plugin (модел на HashiCorp go-plugin) — plugin-ът е отделен
  процес, пада без да събори ядрото, върви под собствен потребител/seccomp.
- **Езици:** Go (native), Python (за анализ), всичко, което говори gRPC.
- **Типове plugin:** `driver.*` (осемте по-горе), `protocol.*` (нова емулирана услуга),
  `detector.*` (нова детекция), `content.*` (генератор на съдържание/персона),
  `export.*` (нов изходен формат).
- **Манифест** с декларирани capabilities и **изисквани права** — plugin не може да
  поиска изходящ достъп, ако containment политиката го забранява.
- **Подпис** на plugin-и; официален и общностен канал разделени.

## 4. Overlay режим — примамки без да пипаш мрежата ★
Най-голямата пречка пред внедряване на deception е "трябва да ми пипнете VLAN-ите".

Overlay режим: малък **Presence Agent** (или контейнер) в даден сегмент поема
неизползвани IP адреси (ARP responder) и **тунелира** трафика през WireGuard към
централните примамки. Резултат:
- нулева промяна в суичове, firewall и VLAN-и;
- примамките физически живеят в изолирания сегмент, но се *явяват* във всеки сегмент;
- инсталация за 10 минути в среда, която не контролираме.

Точно това прави продукта продаваем на MSSP-та и на компании без мрежов екип.
(Риск: тунелът е път навън от мръсна зона → криптиран, еднопосочен, само
предварително декларирани портове, kill switch, виж `docs/04`.)

**Реализирано** (`internal/presence`, `cmd/mirage-presence`): агентът поема
свободни адреси и мултиплексира всяка връзка към хъба; хъбът — не агентът —
решава кои услуги се носят; при паднал тунел агентът не обслужва нищо.

Транспортът е **взаимен TLS** със собствен CA (`miragectl presence-ca`).
Собствен CA, а не изискване за външен PKI: функция, която иска отделен PKI
проект, преди да тръгне, е функция, която остава изключена — а изключена тук
значи токенът на агента и всичко, което атакуващият пише на примамката,
пътуват в чист текст през чужда мрежа. С `presence.tls.ca_file` на хъба агент
без сертификат се отрязва, преди да подаде токен, така че токен, прочетен от
компрометиран агент, не е достатъчен. `ca.key` остава на хъба.

## 5. Изисквания за универсалност (definition of done за всяка функция)
1. Работи с поне два драйвера от съответната категория, единият OSS.
2. Има `capability` декларация — UI скрива това, което драйверът не може.
3. Има degraded режим (напр. без VMI → мрежова реконструкция; без mirror → in-line tap).
4. Не приема мрежов дизайн — работи и в overlay режим.
5. Не приема Windows/AD — Linux-only и cloud-only средите са първи клас.
6. Няма зашити имена, езици, часови зони или конвенции — всичко идва от персона.
