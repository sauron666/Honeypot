# 07 — Пътна карта (универсална версия)

Оценките са в "човеко-седмици при 1 разработчик + AI асистенция", реалистични.
Всяка фаза има **критерий за приемане** — без него фазата не е готова.

> Промяна спрямо първата версия: универсалността не е фаза 5, а **вградена от
> фаза 0**. Драйверните абстракции, персоните и Deception-as-Code струват малко,
> ако са от началото, и са почти невъзможни за вкарване после.

---

> **Състояние към 2026-08-28:** фази 0–3 са практически завършени. От 20 идеи в
> каталога 17 са реализирани напълно или частично. 17 емулирани протокола,
> 13 драйвера, ~36 000 реда Go, 23 тестови пакета (всичко зелено на Linux и
> Windows). Основното, което остава: VMI hypervisor-glue (нужен Xen dom0,
> виж ADR-010), golden templates (Packer/cloud-init) и фаза 6 (SaaS/cloud).

## Фаза 0 — Гръбнак и абстракции  (3–4 седмици) — ✅ ЗАВЪРШЕНА
**Цел:** едно събитие от край до край + правилните шевове от първия ден.

- [x] Monorepo, Go workspace, CI (fmt, vet, test, race, govulncheck)
- [x] Event schema v0 (OCSF плик + `mirage` разширение) + hash chain
- [x] In-process шина + append-only JSONL evidence store (NATS/ClickHouse отложени)
- [x] **Driver Registry + осемте интерфейса** с `capabilities` декларации
- [x] `ComputeDriver`: `inproc`, `podman`, `libvirt`, `proxmox`
- [x] `FabricDriver`: `nftables` (налага + проверява) и `probe` (тества реалността)
- [x] `ObserverDriver`: `none` + `drakvuf` (parsing/mapping готови, hypervisor-glue остава)
- [x] `mirage-director` v0: REST API, evidence pipeline, конзола
- [x] `mirage-ui` v0: engagements, събития, детайл, session transcript, verify
- [ ] Golden template: `deb12-web` (Packer) — липсва
- [ ] `mirage-tap` v0: pcap + Suricata EVE ingest — отложен

---

## Фаза 1 — MVP: широчина + внедримост  (8–10 седмици) — ✅ ЗАВЪРШЕНА
**Цел:** продукт, който непознат човек може да инсталира и от който има полза за час.

- [x] 17 протокола: ssh, http, telnet, ftp, redis, mysql, mssql, vnc, smtp, snmp, modbus, ldap, smb, kerberos, mcp, tokens, generic
- [x] Multi-IP projection (`addresses:` на примамка)
- [x] **Персони** — 5 персони (linux/web, linux/db, linux/backup, linux/fileserver, windows/dc)
- [x] **Deception-as-Code**: `miragectl plan/apply` с реконсилиране без рестарт
- [x] `mirage-tokens`: 10 типа (url, web-image, office-doc, aws-key, api-token, db-connection, ssh-key, credential, llm-key, prompt-canary) + callback + watcher + .docx
- [x] **Sinks**: stdout, file, webhook, syslog, elastic (ECS), splunk (HEC)
- [x] **`mirage-forge`**: авто-Sigma/Suricata/YARA/STIX + инцидентен доклад
- [x] **Профил P0 "honeypot в кутия"**: `make build && ./bin/mirage-director`
- [x] `ComputeDriver: proxmox` (Proxmox VE през pvesh CLI)
- [ ] SSH/PTY session replay в UI — липсва
- [ ] Export: STIX 2.1 → MISP; TheHive alert — отложен

---

## Фаза 2 — Дълбочина: VMI, Windows, Overlay  (10–12 седмици) — ✅ ЗАВЪРШЕНА ★
- [x] `ObserverDriver`: DRAKVUF parsing/mapping тествано; hypervisor-glue остава (ADR-010)
- [x] SMB2: negotiate, session setup (NetNTLMv2), tree connect + **файлови операции** (Create/Read/Write/Close/QueryDirectory/QueryInfo)
- [x] **`mirage-presence` — overlay режим** ★: хъб + агент, мултиплексиран тунел, fail-closed
- [x] **Взаимен TLS** за overlay тунела + собствен CA (`miragectl presence-ca`)
- [x] **`mirage-breadcrumbs`** агент v1: 10 вида следи (rdp, ssh-config, bash/ps-history, aws, git, winscp, db-config, creds, llm-key), обратим манифест
- [x] **`mirage-assure` част 2 — Deception Assurance** (синтетичен атакуващ)
- [x] **Пълни VM примамки** (`internal/farm`): provisioner, containment gate, baseline, revert, burn
- [ ] Windows golden templates (Win10/11, Server 2019/2022) — липсват
- [ ] RDP видео реконструкция — отложена
- [ ] Anti-fingerprinting pass #1 — отложен

---

## Фаза 3 — Identity, Ransomware, нови повърхности  (8–10 седмици) — ✅ ЗАВЪРШЕНА ★
- [x] **Kerberos KDC**: enumeration, password spraying, AS-REP roast и kerberoast с **crackable** RC4-HMAC hash (планирана парола, която hashcat 18200/13100 намират)
- [x] Identity deception: LDAP фалшива AD (kerberoast SPN, AS-REP, ESC1, LAPS, GPP cpassword)
- [x] Honey file server: генериран дял с canary файлове
- [x] Ransomware детекция: 6 сигнала + tarpit + извличане на контакти + **SMB write** детекция
- [x] **Honey MCP сървър** (AI agent deception): JSON-RPC, initialize, tools/list, tools/call ★
- [x] **Prompt-injection канари** + **LLM-key** honeytokens
- [x] **Web Labyrinth** (cognitive friction): безкрайна мрежа от страници за скенери
- [ ] Crypto key capture от паметта — нужен VMI
- [ ] DCSync canary, IdentityDriver към реален AD — отложен

---

## Фаза 4 — Реализъм, автопилот, разполагане по пътища  (8–10 седмици) — ✅ ЗАВЪРШЕНА ★
- [x] **Life Engine** (`internal/life`): синтетичен живот като f(seed, now) — логини, логове, lastLogon
- [x] **`mirage-graph` — Attack Path Deception**: Dijkstra, coverage metric, suggest choke points ★
- [x] **Fingerprint Assurance**: Detectability Score + какво издава всяка примамка ★
- [x] **Just-in-Time примамки** (`internal/honeyd/jit.go`): реактивно вдигане при сканиране
- [x] **Watermarking** (`internal/watermark`): 3 техники (zero-width, whitespace, visible DocID) + extract
- [x] **Engagement Economics** (`miragectl economics`): ROI метрика — attacker hours, confirmed incidents, top techniques
- [ ] NACDriver: RADIUS CoA + FreeRADIUS — отложен
- [ ] Insider-threat режим + шаблон за политика/DPIA — отложен
- [ ] Fleet rotation, burn tracking — частично (burn tracking е в farm)

---

## Фаза 5 — Интелект и продуктизация  (10–12 седмици) — ЧАСТИЧНО
- [x] **Attacker Toolkit DB** (`internal/toolkit`): 12 сигнатури + prediction на следваща стъпка
- [x] `mirage-forge`: авто-Sigma/YARA/Suricata/STIX + инцидентен доклад
- [x] **Compliance evidence** (`internal/compliance`): NIS2/DORA/ISO 27001/PCI DSS 4.0/SOC 2/IEC 62443 — 20 контроли, Markdown отчет
- [ ] `mirage-vault`: hash chain, RFC3161, подписан evidence package — отложен
- [ ] Локален LLM аналитик (офлайн) — отложен
- [ ] Multi-tenancy, SSO/SAML — отложен
- [ ] `ComputeDriver: vsphere/hyper-v`; `IdentityDriver: Entra ID/Okta` — отложен
- [ ] Appliance пакетиране (ISO/OVA/Proxmox template), plugin SDK v1 — отложен

---

## Фаза 6 — Разширяване на пазара
- `mirage-cloud` (AWS/Azure/GCP + SaaS/IdP deception) · `mirage-mail` (BEC) ·
  Kubernetes deception · OT/ICS задълбочаване (hardware-in-the-loop) ·
  `mirage-range` (полигон/обучение) · wireless/BYOD ·
  **Global Feed** (opt-in, анонимизиран) — дългосрочният ров.

---

## Обща оценка
| Фаза | Седмици | Кумулативно | Статус |
|---|---|---|---|
| 0 | 4 | 4 | ✅ |
| 1 | 10 | 14 | ✅ |
| 2 | 12 | 26 | ✅ |
| 3 | 10 | 36 | ✅ |
| 4 | 10 | 46 | ✅ |
| 5 | 12 | 58 | ◐ частично |

Междинни полезни точки:
- **след фаза 1** — работещ open-source продукт; ✅ готов
- **след фаза 2** — уникална форензична дълбочина + внедримост навсякъде; ✅ готов
- **след фаза 3** — първите платени пилоти са смислени; ✅ готов

При ограничено време приоритетът е: **0 → 1 → 2 → 3** (всичките завършени).
