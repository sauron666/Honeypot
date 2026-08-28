# 08 — Технологичен стек и структура на репото

## 1. Избор на технологии

| Слой | Технология | Причина |
|---|---|---|
| Control plane, всичко | **Go 1.24** | един статичен бинар, отличен concurrency, лесен on-prem deploy; **единственият език днес** — Rust/Python/React са отложени |
| Шина | in-process (`internal/bus`) | publish/subscribe с subject matching; достатъчно за единичен процес |
| Състояние | **append-only JSONL + SHA-256 hash chain** | tamper-evident, не зависи от БД; streaming verification |
| UI | **вградена конзола** (HTML/JS в бинара, strict CSP) | без Node, без build step, без CDN |
| VMI | **libvmi / DRAKVUF** | единственият сериозен agentless подход върху KVM |
| Виртуализация | **Proxmox VE API / libvirt** | целевата среда |
| Образи | **Packer** + Ansible | възпроизводими golden templates |
| Deploy | Docker Compose (dev), **systemd + бинари** (prod appliance), Helm (по-късно) | on-prem простота |
| Наблюдаемост | OpenTelemetry, Prometheus, Grafana | самонаблюдение |

**Съзнателно НЕ използваме:**
- Kafka (тежък за appliance) · Kubernetes като изискване (усложнява on-prem) ·
  Cowrie/Dionaea като дефолт (фингърпринтваеми) · LLM в решаващия път за alerting.

## 2. Структура на репото (реална, към последния commit)

```
Honeypot/
├── cmd/                            # бинари
│   ├── mirage-director/            # главният процес
│   ├── miragectl/                  # CLI: doctor, plan, apply, verify, events, forge, assure, fingerprint, presence-ca, vms, economics, status
│   ├── mirage-presence/            # Presence Agent (overlay режим)
│   └── mirage-breadcrumbs/         # засява следи на реални endpoint-и
├── internal/
│   ├── event/                      # OCSF схема, ULID, канонична сериализация, hash chain
│   ├── store/                      # append-only JSONL evidence file, streaming verification
│   ├── bus/                        # in-process pub/sub с subject matching
│   ├── engagement/                 # stitching, жизнен цикъл, risk score, economics
│   ├── alert/                      # severity gate, дедупликация, маркер за synthetic
│   ├── honeyd/                     # 17 емулирани протокола + персони + VFS + shell + JIT
│   ├── tokens/                     # 10 типа honeytokens + callback + watcher + .docx + prompt canary
│   ├── breadcrumbs/                # следи на реални endpoint-и (10 вида) + обратим плантер
│   ├── presence/                   # overlay: хъб + агент + мултиплексиран тунел + взаимен TLS + CA
│   ├── farm/                       # пълни VM примамки: provisioner, containment gate, burn, revert
│   ├── life/                       # синтетичен живот: f(seed, now) → логини, логове, lastLogon
│   ├── graph/                      # attack path deception: Dijkstra, coverage, suggest
│   ├── toolkit/                    # attacker toolkit DB: 12 сигнатури + prediction
│   ├── forge/                      # авто-Sigma/Suricata/YARA/STIX + инцидентен доклад
│   ├── assure/                     # самотест + Detectability Score (fingerprint)
│   ├── ransomware/                 # 6 сигнала + tarpit + извличане на контакти от бележката
│   ├── compliance/                 # NIS2/DORA/ISO/PCI/SOC2/IEC 62443: 20 контроли, Markdown отчет
│   ├── watermark/                  # 3 техники (zero-width, whitespace, DocID) + extract
│   ├── config/                     # YAML манифест, валидация, plan диф
│   ├── app/                        # сглобяване на deployment (bin + e2e ползват него)
│   ├── api/                        # REST API + вградена конзола (strict CSP)
│   │   └── web/                    # index.html, app.js, style.css
│   ├── version/                    # build info
│   ├── drivers/                    # ★ драйверни абстракции (ADR-008)
│   │   ├── compute/                # inproc, podman, libvirt, proxmox
│   │   ├── fabric/                 # nftables, probe
│   │   ├── observer/               # none, drakvuf (parsing/mapping готови)
│   │   ├── sink/                   # stdout, file, webhook, syslog, elastic, splunk
│   │   ├── identity/               # (празен — бъдещ)
│   │   └── (nac, forensics, intel) # (празни — бъдещи)
│   └── driverset/                  # регистрация на вградените драйвери
├── profiles/                       # p0-box.yaml, p3-mssp-overlay.yaml, p4-fullvm.yaml, breadcrumbs.example.yaml
├── docs/                           # 00-11 + ADR
│   └── adr/                        # ADR-001,004,007,008,009,010
├── test/
│   └── e2e/                        # пълен атакови сценарий + build constraint guard
├── go.mod, go.sum
├── CLAUDE.md                       # трайно състояние на проекта за AI сесии
└── README.md
```

## 3. Инженерни стандарти
- **Тестове:** unit ≥ 70% на `internal/`; e2e сценарии за всяка фаза от роудмапа.
- **CI gates:** lint, tests, `go vet`, `gosec`, `cargo clippy`, SBOM (syft),
  vulnerability scan (grype), **honeypot-detection suite**.
- **Сигурност на самия продукт:** всички API-та mTLS; без дефолтни креденшъли
  (инсталаторът генерира); подписани release-и; reproducible builds; threat model
  преразглеждан всяка фаза.
- **Versioning:** SemVer; event schema има собствена версия и compat матрица.
- **Никакви тайни в repo** — gitleaks в pre-commit и в CI.
- **Всяка нова функция минава ревю срещу `docs/04` (containment) преди merge.**

## 4. Първи технически рискове (и как ги смекчаваме)
| Риск | Смекчаване |
|---|---|
| DRAKVUF/libvmi е крехък при нови Windows build-ове | абстрахираме зад интерфейс; fallback към eBPF/ETW-от-хоста; поддържаме фиксиран набор образи |
| Обем от VMI телеметрия | tracing само при активна сесия + adaptive sampling + ClickHouse |
| Escalation handoff (L1→L3) е нетривиален | прототип още във фаза 1 като spike; ако не стане прозрачно — приемаме "reset" на връзката, което е приемливо за повечето вектори |
| Anti-fingerprinting е безкрайна битка | превръщаме го в CI gate (`mirage-assure`), не в еднократна задача |
| Осем абстракции = over-engineering | всяка абстракция има ≥2 имплементации от ден 1; ако категория остане с една, я премахваме |
| Overlay тунел е нова атакувана повърхност | ADR-009 контроли + задължителен pentest на `mirage-presence` |
| Твърде много идеи → нищо завършено | `docs/11-IDEAS.md` е приоритизиран backlog, не план; фази 0–3 са замразени |
| Правен риск от `brokered` egress | по подразбиране `sinkhole`; `brokered` изисква явно подписано одобрение в UI |
