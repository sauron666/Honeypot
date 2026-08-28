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

## 5. Слой на абстракциите (универсалност)

Ядрото не познава нито един вендор. Между компонентите и външния свят стоят осем
драйверни интерфейса — `Compute`, `Fabric`, `NAC`, `Identity`, `Observer`,
`Forensics`, `Sink`, `Intel` (пълна матрица: `docs/10-INTEGRATIONS.md`).

```
        mirage-director / brain / forge          ← бизнес логика, нула вендори
                      │
        ┌─────────────┴─────────────┐
        │   Driver Registry         │  ← capability декларации на всеки драйвер
        └─────────────┬─────────────┘
   ┌────────┬─────────┼─────────┬──────────┬─────────┐
 Compute  Fabric   Identity  Observer  Forensics   Sink
 libvirt  nftables    AD      libvmi   Velociraptor syslog
 proxmox  ovs       EntraID   eBPF     Wazuh        Elastic
 vsphere  opnsense  Okta      netrecon EDR API      Splunk
 podman   cisco     FreeIPA   agent    GRR          TheHive
 aws/az   cloud-sg  Keycloak  snapshot osquery      MISP
```

Правила:
- Всяка функция трябва да работи с **поне два драйвера** от категорията си.
- Всеки драйвер декларира `capabilities`; UI и планировчикът скриват невъзможното.
- Всяка функция има **degraded режим** (няма VMI → мрежова реконструкция;
  няма mirror → in-line tap; няма AD → LDAP/IdP драйвер; няма хипервайзор → контейнери).
- Външни разширения през gRPC plugin SDK, без форк на ядрото.

## 6. Три режима на разполагане в мрежата

| Режим | Как примамките се появяват | Изисква | Кога |
|---|---|---|---|
| **Inline** | реални интерфейси в реални VLAN-и | мрежов проект | пълен контрол над средата |
| **Overlay** ★ | Presence Agent поема свободни IP-та и тунелира (WireGuard) към централните примамки | нищо | MSSP, чужда мрежа, бърз старт |
| **Cloud** | инстанции/контейнери в VPC + SG правила | cloud права | cloud-native среди |

Overlay режимът е стратегически: премахва най-честата причина deception проекти
да не тръгнат — "трябва да ви пипнем мрежата".

## 7. Deception-as-Code

Кампаниите се описват декларативно (`Campaign`, `Persona`, `Token`, `Breadcrumb`,
`Containment`) и се прилагат с `miragectl plan/apply`. Git е източникът на истина;
drift detection засича както грешка в конфигурацията, така и **атакуващ, който трие
следи**. Един и същ манифест работи на Proxmox, vSphere и в AWS — само драйверът
е различен. Детайли: `docs/11-IDEAS.md §1`.

## 8. Ключови архитектурни решения (ADR резюме)

| ADR | Решение | Причина |
|---|---|---|
| 001 | Go за control/data plane, Rust за hot-path capture | един бинар, лесен deploy, добра concurrency; Rust само където е нужен zero-copy |
| 002 | NATS JetStream, не Kafka | по-лек за on-prem appliance, вграден store-and-forward, mTLS |
| 003 | ClickHouse за телеметрия, Postgres за състояние | 10^9 syscall реда/седмица не влизат в Postgres |
| 004 | VMI през libvmi/DRAKVUF, не in-guest агент | anti-detection е стълб №1 |
| 005 | Proxmox/libvirt като първи driver, vSphere/cloud после | целевата лаборатория и mid-market |
| 006 | OCSF като канонична схема, ECS/CEF като export | OCSF е където отива пазарът (AWS/Splunk/CrowdStrike) |
| 007 | Egress през собствен broker, не през прод firewall | containment трябва да е наша отговорност, не конфигурационна |

| 008 | Осем драйверни абстракции, нула вендори в ядрото | продуктът трябва да работи навсякъде, не само в една лаборатория |
| 009 | Overlay режим като първокласен, не като хак | най-голямата пречка пред внедряване е мрежовата промяна |
| 010 | Deception-as-Code като основен интерфейс, UI отгоре | преносимост, одит, GitOps, MSSP мащаб |

Пълните ADR-и: `docs/adr/`.
