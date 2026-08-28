# 07 — Пътна карта

Оценките са в "човеко-седмици при 1 разработчик + AI асистенция", реалистични, не
оптимистични. Всяка фаза има **критерий за приемане** — без него фазата не е готова.

---

## Фаза 0 — Скелет и гръбнак  (2–3 седмици)
**Цел:** една истинска примамка, едно истинско събитие, от край до край.

- [ ] Monorepo, Go workspace, Makefile, golangci-lint, CI (GitHub Actions)
- [ ] Event schema v0 (OCSF плик + `mirage` разширение) + Go типове + валидация
- [ ] NATS JetStream + ClickHouse + Postgres + MinIO чрез docker-compose (dev)
- [ ] `mirage-director` v0: инвентар на примамки, gRPC/REST, миграции
- [ ] `mirage-provisioner` v0: Proxmox driver — clone, start, snapshot, revert
- [ ] `mirage-tap` v0: пълен pcap на 666 + Suricata EVE ingest + сесиен индекс
- [ ] `mirage-ui` v0: списък събития, детайл на сесия, изтегляне на pcap
- [ ] Golden template: `tpl-deb12-web` (Packer)

**Приемане:** SSH brute force към Debian примамка → в UI виждам сесията, пълния
pcap и списъка изпълнени команди; всичко с един `engagement_id`.

---

## Фаза 1 — MVP: широчина  (6–8 седмици)
**Цел:** продукт, който е полезен още от първия ден.

- [ ] `mirage-honeyd`: 12 протокола (SSH, HTTP/S, SMB, RDP-front, FTP, Telnet,
      MySQL, MSSQL, Postgres, Redis, VNC, SNMP) с per-deploy рандомизация
- [ ] Multi-IP projection (един процес → 200 IP адреса)
- [ ] `mirage-tokens`: 10 типа токени + callback receiver + minting API
- [ ] `mirage-gateway` v1: sinkhole режим, DNS/HTTP responder, kill switch,
      всички hard-coded предпазители от `docs/04 §4`
- [ ] Alerting: webhook, syslog, email, Slack/Teams/Telegram
- [ ] Export: ECS→Elastic/Wazuh, CEF→syslog, STIX→MISP
- [ ] SSH/PTY session replay в UI (asciinema)
- [ ] RBAC, audit log, multi-site

**Приемане:** внедрено в лабораторията, работи 30 дни без намеса, хваща
симулирана атака (Nmap → креденшъл от token → lateral към примамка) и произвежда
разбираем инцидентен доклад.

---

## Фаза 2 — Дълбочина: VMI и Windows  (8–10 седмици) ★
**Цел:** това, което конкуренцията не може.

- [ ] `mirage-observer`: libvmi/DRAKVUF интеграция върху KVM
      - process/file/registry/module tracing без агент
      - тригер-базиран memory dump + YARA върху жива памет
- [ ] Windows golden templates (Win10/11, Server 2019/2022) + domain join
- [ ] Escalation Broker: L1 → L3 handoff с replay на сесията
- [ ] RDP реконструкция (видео + clipboard + drive redirect carve)
- [ ] SMB/DCERPC/WinRM реконструктори
- [ ] Anti-fingerprinting pass #1: SMBIOS/DMI, CPUID, дискови модели, MAC OUI
- [ ] `mirage-breadcrumbs` агент v1 (Windows) + Velociraptor artifacts

**Приемане:** оператор с Cobalt Strike/Sliver прави пълна верига в примамка;
получаваме процесното дърво, инжекциите, C2 конфигурацията и видео на екрана —
без нищо, инсталирано в госта.

---

## Фаза 3 — Identity & Ransomware  (6–8 седмици) ★
- [ ] Honey forest автоматизация (AD + ADCS deploy през provisioner)
- [ ] Kerberoast / AS-REP / DCSync / ESC1 капани + детекции
- [ ] Honey GPO, SYSVOL, LAPS токени
- [ ] Honey file server: FUSE генерирана FS (безкрайна дълбочина, реални magic bytes)
- [ ] Ransomware детекция: SMB-слой ентропия/скорост + VMI crypto hooks
- [ ] **Crypto key capture** от паметта + структурирано съхранение
- [ ] Tarpit режим (експоненциална latency)
- [ ] Auto-response: snapshot → IOC push към EDR → revert → продължаване

**Приемане:** реален ransomware sample (в изолирана среда) е засечен < 5s,
ключът е уловен, примамката е върната, IOC-ите са в SIEM-а, генериран е YARA.

---

## Фаза 4 — Реализъм и автопилот  (6–8 седмици) ★
- [ ] **Life Engine**: aging pass, синтетични потребители, фонов трафик,
      генерирано съдържание по вертикал (вкл. кирилица за BG клиенти)
- [ ] **Mimicry Autopilot**: пасивно профилиране на реалната мрежа (Zeek/AD read-only)
      → автоматично предложение за примамки, имена, IP-та, портове, VLAN-и
- [ ] **Deception Coverage Score**: метрика по сегмент и по ATT&CK техника
- [ ] Fleet rotation & burn tracking
- [ ] Anti-fingerprinting pass #2 + автоматични detection-тестове в CI
- [ ] FreeRADIUS rogue-device redirection интеграция

**Приемане:** външен red team (наети, с 8 часа) не може да определи с увереност
кои хостове в сегмента са примамки; coverage score-ът е обясним пред CISO.

---

## Фаза 5 — Интелект и продуктизация  (8–10 седмици)
- [ ] `mirage-brain`: session stitching, ATT&CK auto-mapping, actor clustering
- [ ] `mirage-forge`: авто-Sigma/YARA/Suricata + валидация + push към SIEM
- [ ] `mirage-vault`: hash chain, RFC3161, evidence package + подписан експорт
- [ ] Автоматичен инцидентен доклад (PDF) + изпълнителен дайджест
- [ ] Multi-tenancy за MSSP, per-tenant криптиране, billing метрики
- [ ] Appliance пакетиране: ISO / OVA / Proxmox шаблон, инсталатор < 20 мин.
- [ ] Документация, обучение, demo среда
- [ ] **Външен pentest на самата платформа** (задължително преди GA)

**Приемане:** непознат човек инсталира от ISO и има работеща deception мрежа
за под 1 час, без да чете кода.

---

## Фаза 6+ — Разширения
- Cloud deception (AWS/Azure/GCP примамки, fake IAM, fake S3)
- Kubernetes deception (honey namespace, fake secrets, honey admission webhook)
- OT/ICS задълбочаване (реален PLC hardware-in-the-loop)
- Active Defense контрол (легален sticky/tarpit за web приложения)
- Deception-as-a-Service / MSSP портал
- Собствен threat feed от агрегираната (анонимизирана, opt-in) телеметрия ★
  *— това е дългосрочният ров: никой друг няма високо-интерактивни данни в този обем.*

---

## Обща оценка
| Етап | Седмици | Кумулативно |
|---|---|---|
| 0 | 3 | 3 |
| 1 | 8 | 11 |
| 2 | 10 | 21 |
| 3 | 8 | 29 |
| 4 | 8 | 37 |
| 5 | 10 | 47 |

**~11 месеца до пазарно-годен продукт при един разработчик.**
Полезен за собствената лаборатория: **след фаза 1 (~3 месеца).**

Приоритет при ограничено време: **0 → 1 → 2 → 3**. Фази 2 и 3 са това, което
прави продукта неповторим; 4 и 5 са това, което го прави продаваем.
