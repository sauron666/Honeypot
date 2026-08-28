# 08 — Технологичен стек и структура на репото

## 1. Избор на технологии

| Слой | Технология | Причина |
|---|---|---|
| Control plane, услуги | **Go 1.23+** | един статичен бинар, отличен concurrency, лесен on-prem deploy |
| Hot-path capture, VMI бридж | **Rust** (+ C FFI към libvmi) | zero-copy, без GC паузи при 10 Gbps / syscall поток |
| Анализ, ML, парсери | **Python 3.12** (plugin sandbox) | екосистема (Volatility3, YARA, dpkt, scapy) |
| UI | **TypeScript + React + Vite**, TanStack Query, Tailwind | стандарт, бърз |
| Състояние | **PostgreSQL 16** | транзакции, релации |
| Телеметрия | **ClickHouse** | 10^9 реда, компресия, бързи агрегации |
| Обекти | **MinIO** (S3, object-lock) | WORM за evidence |
| Шина | **NATS JetStream** | лек, store-and-forward, mTLS, за appliance |
| Кеш/state | **Redis** | rate limits, escalation broker |
| Мрежов анализ | **Suricata**, **Zeek** | не преоткриваме колелото |
| VMI | **libvmi / DRAKVUF** | единственият сериозен agentless подход върху KVM |
| Виртуализация | **Proxmox VE API / libvirt** | целевата среда |
| Образи | **Packer** + Ansible | възпроизводими golden templates |
| Deploy | Docker Compose (dev), **systemd + бинари** (prod appliance), Helm (по-късно) | on-prem простота |
| Наблюдаемост | OpenTelemetry, Prometheus, Grafana | самонаблюдение |

**Съзнателно НЕ използваме:**
- Kafka (тежък за appliance) · Kubernetes като изискване (усложнява on-prem) ·
  Cowrie/Dionaea като дефолт (фингърпринтваеми) · LLM в решаващия път за alerting.

## 2. Структура на репото

```
mirage/
├── cmd/                        # точки за вход (по един бинар на компонент)
│   ├── mirage-director/
│   ├── mirage-provisioner/
│   ├── mirage-tap/
│   ├── mirage-gateway/
│   ├── mirage-honeyd/
│   ├── mirage-tokens/
│   ├── mirage-brain/
│   ├── mirage-forge/
│   ├── mirage-breadcrumbs/     # агент (Win/Lin/Mac)
│   └── miragectl/              # CLI
├── internal/
│   ├── event/                  # OCSF схема, валидация, hash chain
│   ├── bus/                    # NATS абстракция
│   ├── store/                  # postgres, clickhouse, minio
│   ├── engagement/             # stitching, жизнен цикъл
│   ├── attack/                 # ATT&CK mapping
│   ├── policy/                 # containment политики (hard-coded предпазители)
│   ├── provision/              # drivers: proxmox, libvirt, podman
│   ├── protocols/              # емулатори по протокол
│   ├── recon/                  # реконструктори: ssh, rdp, smb, http
│   ├── deception/              # tokens, breadcrumbs, personas, content gen
│   ├── life/                   # Life Engine
│   ├── ransomware/             # детекция, tarpit, key capture
│   └── export/                 # siem, stix, sigma, yara
├── observer/                   # Rust + C: libvmi/DRAKVUF бридж
│   ├── src/
│   └── ffi/
├── analytics/                  # Python plugins (sandboxed)
├── web/                        # React UI
├── templates/                  # Packer + Ansible за golden images
│   ├── win11-corp/ winsrv2022-file/ deb12-web/ nas-appliance/
├── deploy/
│   ├── compose/ systemd/ iso/ helm/
├── docs/                       # тази документация
├── test/
│   ├── e2e/                    # пълни атакови сценарии
│   ├── redteam/                # honeypot-detection тестове (CI gate)
│   └── corpus/                 # реални протоколни отговори за сравнение
└── tools/
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
| Anti-fingerprinting е безкрайна битка | превръщаме го в CI gate, не в еднократна задача |
| Правен риск от `brokered` egress | по подразбиране `sinkhole`; `brokered` изисква явно подписано одобрение в UI |
