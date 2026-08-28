# 01 — Архитектура

## 1. Четирите плоскости

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE   (доверена зона — НИКОГА не е достъпна от decoy мрежата) │
│  mirage-director · mirage-provisioner · mirage-brain · mirage-forge       │
│  mirage-ui · mirage-vault · Postgres · ClickHouse · NATS · MinIO          │
└───────────▲──────────────────────────────────┬───────────────────────────┘
            │ (само изходящи pull/push от      │ (out-of-band управление
            │  сензорите; data-diode модел)    │  на хипервайзора)
┌───────────┴──────────┐          ┌────────────▼──────────────────────────┐
│  OBSERVATION PLANE   │          │  DATA PLANE (мръсна зона / VLAN 666)  │
│  mirage-observer     │◄── VMI ──┤  Decoy VM-и (Windows/Debian/appliance)│
│    (на всеки Proxmox │          │  mirage-honeyd ферма (емулация)       │
│     node, извън guest)│          │  honey file server (FUSE tarpit)      │
│  mirage-tap          │◄─ SPAN ──┤  honey AD / ADCS                      │
│    (Suricata+Zeek+   │          └────────────┬──────────────────────────┘
│     custom recon)    │                       │
└──────────────────────┘          ┌────────────▼──────────────────────────┐
                                  │  mirage-gateway (egress broker)       │
                                  │  MITM · sinkhole · rate-limit · KILL  │
                                  └────────────┬──────────────────────────┘
                                               │ (силно ограничен интернет)
┌──────────────────────────────────────────────▼───────────────────────────┐
│  SENSOR PLANE (в РЕАЛНАТА мрежа)                                         │
│  mirage-breadcrumbs агент на реални endpoint-и · honeytoken callbacks    │
│  Velociraptor artifacts · AD honey обекти                                │
└──────────────────────────────────────────────────────────────────────────┘
```

### Защо това разделение
- **Data plane е компрометируем по дизайн.** Приемаме, че атакуващият става root
  в decoy-а. Затова там няма нищо наше — нито агент, нито креденшъл, нито път назад.
- **Observation plane наблюдава отвън.** VMI чете паметта на госта през KVM;
  мрежата се снема от mirror порт. Атакуващият не може да изключи това, което не вижда.
- **Control plane е недостижим.** Мрежово: еднопосочен поток (сензорите
  push-ват към брокера; decoy VLAN няма маршрут до control VLAN изобщо).
- **Sensor plane е в реалната мрежа** и само *подхвърля* примамки и *приема* callbacks.

## 2. Поток на едно събитие

```
attacker → decoy
   ├─ мрежа      → mirror port → mirage-tap (Suricata/Zeek/reconstructors)
   ├─ syscall/   → KVM/libvmi  → mirage-observer (DRAKVUF-style tracing)
   │   файл/registry/process
   ├─ услуга     → mirage-honeyd (структурирани app-level логове)
   └─ egress     → mirage-gateway (MITM, JA4, DNS, C2 класификация)
                              │
                              ▼
                    NATS JetStream (`mirage.events.*`)
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
             normalizer (OCSF)     artifact uploader → MinIO (pcap/mem/sample/video)
                    │                    │
                    ▼                    ▼
              ClickHouse            mirage-vault (hash chain + RFC3161 timestamp)
                    │
                    ▼
              mirage-brain  → session stitching → ATT&CK graph → risk score
                    │
        ┌───────────┼────────────┬──────────────┐
        ▼           ▼            ▼              ▼
     alerting   mirage-forge   mirage-ui   export (SIEM/SOAR/MISP)
                (Sigma/YARA/    (replay)
                 Suricata/STIX)
```

## 3. Нива на взаимодействие (hybrid engagement)

MIRAGE не избира между low и high interaction — **ескалира** според поведението:

| Ниво | Носител | Кога | Цена |
|---|---|---|---|
| **L0 — Presence** | ARP/ICMP responder, отворени портове | винаги, стотици IP-та | ~0 |
| **L1 — Emulation** | `mirage-honeyd` (Go), app-level логика | при connect | нищожна |
| **L2 — Container** | Podman/Docker с истински сървър (nginx, MySQL) | при валиден protocol handshake | ниска |
| **L3 — Full VM** | KVM linked clone, истински OS | при автентикация / expl. опит | 1-4 GB RAM |
| **L4 — Sticky VM** | dedicated VM, задържа сесията, снапшоти на всяка стъпка | при confirmed hands-on-keyboard | пълна |

**Escalation Broker** (част от `mirage-director`) прави прехвърлянето прозрачно:
TCP сесията се "предава" от L1 към L3 чрез connection handoff + replay на вече
разменените байтове, така че атакуващият не вижда прекъсване. Това е техническото
сърце на продукта — дава ни мащаба на Acalvio и дълбочината на пълна VM.

## 4. Multi-node / multi-site

- Един **Director** управлява N **Site**-а (Proxmox клъстер, cloud VPC, OT сегмент).
- Всеки Site има локален **Site Controller** (observer + tap + gateway + буфер),
  който работи автономно при загуба на връзка (store-and-forward в JetStream).
- Multi-tenancy на ниво Site и на ниво Tenant (за MSSP): RBAC, отделни ключове за
  криптиране на evidence, отделни retention политики.

## 5. Ключови архитектурни решения (ADR резюме)

| ADR | Решение | Причина |
|---|---|---|
| 001 | Go за control/data plane, Rust за hot-path capture | един бинар, лесен deploy, добра concurrency; Rust само където е нужен zero-copy |
| 002 | NATS JetStream, не Kafka | по-лек за on-prem appliance, вграден store-and-forward, mTLS |
| 003 | ClickHouse за телеметрия, Postgres за състояние | 10^9 syscall реда/седмица не влизат в Postgres |
| 004 | VMI през libvmi/DRAKVUF, не in-guest агент | anti-detection е стълб №1 |
| 005 | Proxmox/libvirt като първи driver, vSphere/cloud после | целевата лаборатория и mid-market |
| 006 | OCSF като канонична схема, ECS/CEF като export | OCSF е където отива пазарът (AWS/Splunk/CrowdStrike) |
| 007 | Egress през собствен broker, не през прод firewall | containment трябва да е наша отговорност, не конфигурационна |

Пълните ADR-и: `docs/adr/`.
