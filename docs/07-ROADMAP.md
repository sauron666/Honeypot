# 07 — Пътна карта (универсална версия)

Оценките са в "човеко-седмици при 1 разработчик + AI асистенция", реалистични.
Всяка фаза има **критерий за приемане** — без него фазата не е готова.

> Промяна спрямо първата версия: универсалността не е фаза 5, а **вградена от
> фаза 0**. Драйверните абстракции, персоните и Deception-as-Code струват малко,
> ако са от началото, и са почти невъзможни за вкарване после.

---

> **Състояние към 2026-08-28:** фаза 0 е завършена; от фаза 1 са готови
> персоните, шест протокола, sink драйверите, конзолата и профил P0.

## Фаза 0 — Гръбнак и абстракции  (3–4 седмици) — ✅ ЗАВЪРШЕНА
**Цел:** едно събитие от край до край + правилните шевове от първия ден.

- [x] Monorepo, Go workspace, CI (fmt, vet, test, race, govulncheck)
- [x] Event schema v0 (OCSF плик + `mirage` разширение) + hash chain
- [ ] NATS + ClickHouse + Postgres + MinIO (за момента: in-process шина + JSONL evidence store)
- [x] **Driver Registry + осемте интерфейса** с `capabilities` декларации
- [x] `ComputeDriver`: `inproc`, `podman` **и** `libvirt`
- [ ] `FabricDriver`: вграден `nftables/linux-bridge`
- [x] `mirage-director` v0: REST API, evidence pipeline, конзола
- [ ] `mirage-tap` v0: pcap + Suricata EVE ingest + сесиен индекс
- [x] `mirage-ui` v0: engagements, събития, детайл, session transcript, verify
- [ ] Golden template: `deb12-web` (Packer)

**Приемане:** SSH brute force към примамка → сесия, pcap и изпълнени команди в UI,
с общ `engagement_id`. Същият сценарий минава и през `podman`, и през `libvirt`
драйвер, без промяна в кода на ядрото.

---

## Фаза 1 — MVP: широчина + внедримост  (8–10 седмици)
**Цел:** продукт, който непознат човек може да инсталира и от който има полза за час.

- [~] `mirage-honeyd`: 6 протокола (ssh, http, telnet, ftp, redis, generic) с per-deploy рандомизация; остават SMB, RDP, MySQL/MSSQL, VNC, SNMP, OT и multi-IP projection
- [~] **Персони** — три Linux персони с виртуална ФС, подхвърлени тайни и
      стабилен per-deployment seed; остават Deception Packs, i18n и още 12 персони
- [ ] **Deception-as-Code**: `miragectl plan/apply/destroy` + drift detection
- [ ] `mirage-tokens`: 10 типа + callback receiver + minting API
- [ ] `mirage-gateway` v1: `sinkhole`, kill switch, всички hard-coded предпазители
- [ ] `ComputeDriver: proxmox`, `FabricDriver: opnsense` (втори драйвер за реалност)
- [~] Sinks: stdout, file, webhook, syslog RFC5424; остават ECS/Elastic, Splunk HEC, чат
- [ ] Export: STIX 2.1 → MISP; TheHive alert
- [ ] SSH/PTY session replay в UI
- [x] **Профил P0 "honeypot в кутия"**: `make build && ./bin/mirage-director`

**Приемане:** трима външни доброволци инсталират P0 профила по документацията,
без наша помощ, и получават валиден alert за под час. Community release.

---

## Фаза 2 — Дълбочина: VMI, Windows, Overlay  (10–12 седмици) ★
- [ ] `mirage-observer`: libvmi/DRAKVUF върху KVM (процеси, файлове, registry,
      модули, memory dump по тригер, YARA върху жива памет)
- [ ] `ObserverDriver` fallback: eBPF от хоста + чиста мрежова реконструкция
      (за vSphere/Hyper-V/cloud, където няма VMI)
- [ ] Windows golden templates (Win10/11, Server 2019/2022) + domain join
- [ ] Escalation Broker: прозрачен L1 → L3 handoff
- [ ] RDP видео реконструкция, SMB/DCERPC/WinRM реконструктори
- [ ] Anti-fingerprinting pass #1 (SMBIOS/DMI, CPUID, дискови модели, MAC OUI)
- [ ] `mirage-breadcrumbs` агент v1 (Windows/Linux) + Velociraptor artifacts
- [ ] **`mirage-presence` — overlay режим** (WireGuard, ARP takeover) ★
- [ ] **`mirage-assure` част 2 — Deception Assurance** (синтетичен атакуващ,
      проверка на цялата верига до SIEM)

**Приемане:** оператор с Sliver/Cobalt Strike прави пълна верига в примамка →
получаваме процесно дърво, инжекции, C2 конфигурация и видео, без нищо в госта.
Отделно: примамка се разполага в сегмент, до който нямаме мрежов достъп, за 10 минути.

---

## Фаза 3 — Identity, Ransomware, нови повърхности  (8–10 седмици) ★
- [ ] `IdentityDriver: AD + ADCS` — honey forest автоматизация, kerberoast/AS-REP/
      DCSync/ESC1 капани, honey GPO/SYSVOL/LAPS
- [ ] Honey file server: FUSE генерирана FS (безкрайна дълбочина, реални magic bytes)
- [ ] Ransomware детекция (SMB ентропия/скорост + VMI crypto hooks)
- [ ] **Crypto key capture** от паметта + tarpit + auto snapshot/IOC push/revert
- [ ] **`mirage-supply`** — dependency-confusion канари, honey CI runner, honey repo,
      honey K8s namespace/secret
- [ ] **`mirage-ai`** — honey MCP сървър, prompt-injection канари, honey LLM ключове ★
- [ ] Cognitive friction: TCP tarpit, web лабиринт (само входящо)

**Приемане:** реален ransomware sample (изолирано) — засечен < 5s, ключът уловен,
примамката върната, IOC в SIEM, генериран YARA. Отделно: prompt-injection канарче
се задейства от тестов LLM агент.

---

## Фаза 4 — Реализъм, автопилот, разполагане по пътища  (8–10 седмици) ★
- [ ] **Life Engine**: aging pass, синтетични потребители, фонов трафик,
      генерирано съдържание по вертикал и език
- [ ] **`mirage-graph` — Attack Path Deception**: граф на реалната среда,
      автоматично разполагане по критичните пътища, метрика за покритие ★
- [ ] **`mirage-assure` част 1 — Fingerprint Assurance** + Detectability Score
      като CI gate ★
- [ ] **`mirage-jit`** — реактивни примамки в реално време
- [ ] Deception Coverage Score, fleet rotation, burn tracking
- [ ] `NACDriver`: generic RADIUS (CoA) + FreeRADIUS — пренасочване на непознати
      устройства в honeynet вместо блокиране
- [ ] Insider-threat режим + шаблон за политика/DPIA
- [ ] `mirage-watermark`

**Приемане:** нает външен red team (8 часа) не може да определи с увереност кои
хостове са примамки; ≥ 80% от изчислените пътища до Domain Admin пресичат примамка.

---

## Фаза 5 — Интелект и продуктизация  (10–12 седмици)
- [ ] `mirage-brain`: session stitching, ATT&CK auto-mapping, actor clustering,
      **Attacker Toolkit DB** + предсказване на следваща стъпка
- [ ] `mirage-forge`: авто-Sigma/YARA/Suricata + валидация + push към SIEM
- [ ] `mirage-vault`: hash chain, RFC3161, подписан evidence package
- [ ] Локален LLM аналитик (офлайн, извън решаващия път)
- [ ] `mirage-comply` — NIS2/DORA/ISO/PCI/SOC2/IEC 62443 доказателствен пакет
- [ ] Engagement Economics метрики + изпълнителен доклад
- [ ] Multi-tenancy (профил P3), SSO/SAML, per-tenant криптиране, billing
- [ ] `ComputeDriver: vsphere/hyper-v`; `IdentityDriver: Entra ID/Okta`;
      `FabricDriver: Cisco/Fortinet/Palo`
- [ ] Appliance пакетиране (ISO/OVA/Proxmox template), **plugin SDK v1**
- [ ] **Външен pentest на платформата** (задължително преди GA)

**Приемане:** MSSP разполага двама тенанта на различни хипервайзори с различни
SIEM-ове, без нито един ред код от нас.

---

## Фаза 6 — Разширяване на пазара
- `mirage-cloud` (AWS/Azure/GCP + SaaS/IdP deception) · `mirage-mail` (BEC) ·
  Kubernetes deception · OT/ICS задълбочаване (hardware-in-the-loop) ·
  `mirage-range` (полигон/обучение) · wireless/BYOD ·
  **Global Feed** (opt-in, анонимизиран) — дългосрочният ров.

---

## Обща оценка
| Фаза | Седмици | Кумулативно |
|---|---|---|
| 0 | 4 | 4 |
| 1 | 10 | 14 |
| 2 | 12 | 26 |
| 3 | 10 | 36 |
| 4 | 10 | 46 |
| 5 | 12 | 58 |

**~13–14 месеца до пазарно-годен продукт** при един разработчик (с ~2 месеца повече
от първоначалната оценка — цената на универсалността, платена авансово вместо
трикратно по-скъпо после).

Междинни полезни точки:
- **след фаза 1 (~3.5 месеца)** — работещ, публично пуснат open-source продукт;
- **след фаза 2 (~6.5 месеца)** — уникална форензична дълбочина + внедримост навсякъде;
- **след фаза 3 (~8.5 месеца)** — първите платени пилоти са смислени.

При ограничено време приоритетът е: **0 → 1 → 2 → 3**.
