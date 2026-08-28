# 06 — Профили на внедряване

Един продукт, седем начина да се внедри. Профилът е **декларативен пакет**
(`profiles/*.yaml`): избира драйвери, топология, набор примамки, политика на
containment и мащаб. `miragectl init --profile <name>` дава работеща среда.

Целта: **10 минути до първата примамка** в най-простия профил, без да се променя мрежа.

---

## P0 — "Honeypot в кутия" (SMB / първи досег)
| | |
|---|---|
| Compute | `none` — един бинар/контейнер, само L0–L2 |
| Fabric | overlay (Presence Agent) или един NIC в съществуващ VLAN |
| Обхват | 1 сегмент, ~50 виртуални IP, 12 протокола, honeytokens |
| Ресурс | 2 vCPU, 2 GB, 20 GB |
| Containment | `sinkhole`, без изходящ достъп |
| Стойност | сигнал с нулев false positive за 10 минути работа |

Това е и **Community изданието**. Пътят към всичко останало е `upgrade`, не преинсталация.

---

## P1 — Mid-market on-prem (типичният платен клиент)
| | |
|---|---|
| Compute | KVM/libvirt, Proxmox, vSphere или Hyper-V |
| Fabric | съществуващ firewall (OPNsense/Fortinet/Palo) **или** overlay |
| Обхват | 3–10 сегмента, 100–500 примамки L0–L3, AD identity deception, breadcrumbs |
| Ресурс | 1 хипервайзор нод: 32–64 GB RAM, 1–2 TB |
| Observer | VMI, ако compute е KVM; иначе мрежова реконструкция |
| Sinks | SIEM на клиента + EDR |

---

## P2 — Enterprise multi-site
- Централен Director + **Site Controller** на локация (автономен при загуба на връзка).
- Различни драйвери на различни локации (Proxmox в едно ДЦ, vSphere в друго, AWS в трето).
- SSO/SAML, RBAC по локация, отделни retention и криптиращи ключове.
- Deception Coverage Score по локация и бизнес единица.

---

## P3 — MSSP / multi-tenant
- Един Director, N тенанта; per-tenant криптиране на evidence и изолирани данни.
- Тенант = набор от Site-ове + профил + политика; лицензиране по примамки/тенант.
- **Overlay режим по подразбиране** — MSSP не иска да пипа мрежата на клиента.
- Бял етикет (branding), клиентски портал само за четене, billing метрики.
- Автоматично разпръскване на общи deception пакети към всички тенанти.

---

## P4 — Cloud-native
| | |
|---|---|
| Compute | AWS/Azure/GCP инстанции (ephemeral) + контейнери |
| Fabric | Security Groups / NSG / VPC firewall + VPC Traffic Mirroring |
| Примамки | fake S3 bucket, fake IAM role, honey RDS, honey Lambda URL, honey K8s API |
| Токени | AWS/Azure/GCP ключове (CloudTrail/Activity Log детекция), OAuth app canary |
| Observer | eBPF/агент (няма VMI) + cloud audit логове |
| Специфика | decoys се раждат и умират за минути; разходите се следят per-engagement |

---

## P5 — OT / ICS / air-gapped
- **Никакъв изходящ достъп.** `airgap` режим е задължителен, не опция.
- Примамки: Modbus/TCP, S7comm, DNP3, BACnet, EtherNet/IP, IEC-104, HMI, historian.
- Пасивен tap (мрежов TAP хардуер, не SPAN), нулево влияние върху процеса.
- Evidence експорт през подписан носител; без cloud, без телеметрия навън.
- Опция hardware-in-the-loop: реален PLC като примамка, изолиран.
- Съответствие: IEC 62443, NIS2 за енергетика/вода.

---

## P6 — Cyber range / обучение
Същата платформа, друг режим: записаните engagement-и се възпроизвеждат срещу
обучаеми; червеният екип атакува примамки и получава обективен запис на своята
работа. Продава се на университети, академии и вътрешни SOC екипи.

---

## P7 — Home lab / изследователи
Профилът, от който тръгва общността: единичен Proxmox нод, OPNsense, малък AD.
Референтна конфигурация: `profiles/homelab-proxmox-opnsense.yaml`.

Съдържа примерна карта:
```
VLAN 10   PROD           реална мрежа
VLAN 20   MGMT           хипервайзор, firewall, MIRAGE control plane
VLAN 666  DECEPTION      примамките — без маршрут към 10 и 20
VLAN 667  XFER           еднопосочен поток Site Controller → Director
```
и драйвери: `compute=proxmox`, `fabric=opnsense`, `nac=freeradius`,
`identity=ad+adcs`, `forensics=velociraptor`, `sink=<siem по избор>`.

> Специфичните бележки за тази комбинация (Proxmox API права, SPAN от `vmbr`,
> FreeRADIUS rogue-device redirection, Velociraptor artifacts, ADCS honey шаблони)
> живеят в `profiles/homelab-proxmox-opnsense.md`, не в ядрото на архитектурата.

---

## Матрица профил × функция
| Функция | P0 | P1 | P2 | P3 | P4 | P5 | P6 |
|---|---|---|---|---|---|---|---|
| Емулирана ферма (L0–L2) | ● | ● | ● | ● | ● | ● | ● |
| Пълни VM примамки (L3/L4) | – | ● | ● | ● | ● | ○ | ● |
| VMI observer | – | ●¹ | ●¹ | ●¹ | – | ●¹ | ● |
| Ransomware engine | – | ● | ● | ● | ○ | ○ | ● |
| Identity deception | – | ● | ● | ● | ● | – | ● |
| Overlay (без промяна на мрежа) | ● | ● | ● | ● | – | ○ | ● |
| Изходящ C2 наблюдение | – | ○ | ○ | ○ | ○ | **никога** | ○ |
| Multi-tenant | – | – | ○ | ● | ○ | – | ● |

¹ само при KVM-базиран compute (libvirt, Proxmox, Nutanix AHV, XCP-ng).
