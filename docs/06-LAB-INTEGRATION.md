# 06 — Интеграция с SOC лабораторията

Целева среда: **Proxmox VE · OPNsense · FreeRADIUS · Velociraptor · SIEM/EDR ·
Debian · Windows AD + ADCS**.

## 1. Proxmox VE
**Роля:** хипервайзор за примамките и за control plane.

- Отделен нод (или поне отделен ZFS pool + отделен bridge) за deception.
- `mirage-provisioner` използва Proxmox API token с **минимални права**:
  `VM.Clone`, `VM.Config.*`, `VM.PowerMgmt`, `VM.Snapshot`, `Datastore.AllocateSpace`
  върху обособен pool `deception/`.
- Golden templates (Packer-built): `tpl-win11-corp`, `tpl-winsrv2022-file`,
  `tpl-deb12-web`, `tpl-deb12-db`, `tpl-nas-appliance`.
- Linked clones + ZFS snapshots → revert < 15s, дисково потребление ~1 GB/примамка.
- `mirage-observer` работи **на нода** (не в VM): достъп до `/dev/kvm`, libvmi
  срещу QEMU процеса на съответната примамка.
- Мрежа: `vmbr666` (deception), `vmbr20` (mgmt). Примамките нямат NIC в `vmbr20`.
- Мониторинг: Proxmox metrics → MIRAGE (капацитет, ресурси на примамките).

## 2. OPNsense
**Роля:** сегментация, mirror, контрол на изхода.

- VLAN интерфейси: `PROD(10)`, `MGMT(20)`, `DECEPTION(666)`, `XFER(667)`.
- Firewall правила по `docs/04 §2` — deny-by-default, всяка деня към PROD/MGMT alert-ва.
- **Port mirror / SPAN** от `vmbr666` към `mirage-tap` интерфейс
  (в Proxmox: bridge с `tc mirred` или отделен tap порт в promisc).
- Suricata на OPNsense за 666 в **IDS** режим; EVE JSON → MIRAGE.
- Изход от 666 **само** към `mirage-gateway` (single next-hop), gateway решава нататък.
- Unbound DNS: honey зони (`corp.local` honey записи) + sinkhole за `airgap` режим.
- NetFlow/IPFIX от OPNsense → MIRAGE за широк контекст.
- HA/fail-closed: ако gateway-ят е down, 666 губи default route.

## 3. FreeRADIUS (★ силна интеграция)
**Роля:** 802.1X + автоматично пренасочване на непознати устройства в honeynet-а.

- **Rogue device redirection**: устройство, което не минава 802.1X / няма MAB запис,
  вместо да бъде блокирано, получава `Tunnel-Private-Group-Id = 666` →
  озовава се в deception мрежата. Мисли, че е в корпоративната мрежа. Ние го гледаме.
  Това е функция, която FortiDeceptor няма.
- **Honey NAS clients**: фалшив `clients.conf` запис + honeytoken RADIUS secret.
- **Honey WiFi креденшъли** като breadcrumb → всяко използване = alert.
- FreeRADIUS `detail`/SQL логове → MIRAGE (auth събития, MAC, NAS порт).
- Post-auth hook, който уведомява MIRAGE в реално време за пренасочване.

## 4. Velociraptor
**Роля:** доставка на breadcrumbs + hunt при инцидент.

- **MIRAGE Velociraptor artifacts** (наш пакет):
  - `Mirage.Breadcrumbs.Deploy` — плантира и опреснява lures на реални endpoint-и
  - `Mirage.Breadcrumbs.Verify` — проверява дали още са там (tamper detection)
  - `Mirage.Hunt.FromEngagement` — при инцидент MIRAGE генерира hunt с IOC-ите,
    които е наблюдавал, и го стартира в реалната мрежа: *"тази техника била ли е
    използвана и на реални машини?"*
- Двупосочно: Velociraptor client ID ↔ MIRAGE asset; alert в MIRAGE → авто-collection.
- Това е нашият заместител на "трябва да инсталирате нашия агент навсякъде".

## 5. Windows AD + ADCS
**Роля:** identity deception (виж `docs/03 §4`).

Два модела:
| Модел | Описание | Риск | Кога |
|---|---|---|---|
| **Honey forest** (препоръчан) | отделна гора `corp-hq.local` в 666, огледало на реалната по структура и имена, **без trust** | нулев | винаги |
| **Honey OU в реалния AD** | само неактивни token обекти (SPN, AS-REP, ADCS шаблон), без реални права | нисък, но изисква одобрение | за identity capture в прод |

- ADCS в honey гората издава honeytoken сертификати; шаблон, който изглежда
  ESC1-уязвим → всяка заявка алармира и сертификатът се проследява при употреба.
- Honey DC генерира реалистични 4624/4768/4769/4776 събития (Life Engine) →
  атакуващият вижда "жив" домейн.
- Реплика на реалната AD схема (имена на OU, групи, конвенции) се строи от
  **read-only** LDAP четене на продукцията, с анонимизация на реални лица.

## 6. SIEM / EDR
- MIRAGE изпраща: alerts (висок приоритет, ниско количество) + engagement метаданни.
  **Не** изпраща суровата VMI телеметрия (би удавила SIEM-а) — тя остава в ClickHouse
  и се достъпва чрез линк.
- Съответствие: dashboards + saved searches за Splunk/Elastic/Wazuh в комплекта.
- `mirage-forge` push-ва генерираните Sigma правила директно в SIEM-а (с одобрение).
- EDR интеграция: при ransomware улов → hash/IOC веднага в блок-листа (Wazuh
  active-response, Defender IOC API, S1/CrowdStrike API).

## 7. Референтен bill-of-materials за лабораторията

| Компонент | Ресурс |
|---|---|
| MIRAGE control plane VM | 4 vCPU, 8 GB RAM, 100 GB (+ обем за ClickHouse/MinIO) |
| ClickHouse + MinIO | 4 vCPU, 8 GB, 500 GB+ (според retention) |
| mirage-tap | 2 vCPU, 4 GB, 500 GB pcap ring |
| mirage-gateway | 2 vCPU, 2 GB |
| mirage-observer | работи на Proxmox нода, ~1 vCPU + 1 GB |
| honeyd ферма (≈200 IP) | 2 vCPU, 2 GB |
| Windows примамка (L3) | 2 vCPU, 4 GB, linked clone ~1 GB |
| Debian примамка (L3) | 1 vCPU, 1 GB |
| Honey DC + ADCS | 2 vCPU, 4 GB всяка |

Минимум за смислена демонстрация: **~32 GB RAM, 1 TB** на един Proxmox нод.
