# 05 — Модел на данните и съхранение

## 1. Канонична схема: OCSF

Всички събития се нормализират към **OCSF** (Open Cybersecurity Schema Framework).
Причина: OCSF е където отива пазарът (AWS Security Lake, Splunk, CrowdStrike, Cisco)
и ни дава безплатна съвместимост при export. ECS и CEF/LEEF са export формати.

### Базов плик (всяко събитие)
```jsonc
{
  "time": 1735689600123,              // ms epoch
  "class_uid": 1001,                  // OCSF клас (File System Activity)
  "activity_id": 1,
  "severity_id": 3,
  "metadata": {
    "version": "1.3.0",
    "product": { "name": "MIRAGE", "vendor_name": "…", "version": "0.1.0" },
    "sequence": 84213,
    "uid": "01JQ...ULID"
  },
  "mirage": {                          // наше разширение
    "tenant_id": "acme",
    "site_id": "sofia-dc1",
    "decoy_id": "dcy_win10_fin07",
    "decoy_persona": "workstation/finance",
    "engagement_id": "eng_01JQ...",    // ★ ключът към всичко
    "source_plane": "observer|tap|honeyd|gateway|token|breadcrumb",
    "confidence": 100,
    "attack": [{ "tactic": "TA0008", "technique": "T1021.001" }],
    "artifact_refs": ["s3://mirage/art/01JQ.../session.pcap"],
    "chain": { "prev_hash": "…", "hash": "…" }   // Merkle верига
  }
}
```

### Engagement (централният обект)
```
Engagement
├── id, tenant, site, started_at, ended_at, status
├── actor_cluster_id            (fingerprint групиране между инциденти)
├── entry_vector                (token | scan | breadcrumb | lateral)
├── decoys_touched[]
├── phases[]                    (recon → initial access → discovery → … )
├── techniques[]                (ATT&CK, с доказателство за всяка)
├── artifacts[]                 (pcap, memdump, samples, video, keys)
├── iocs[]
├── risk_score
└── narrative                   (генериран разказ + ръчни бележки на анализатора)
```

Всичко, което се случва — мрежов пакет, syscall, натиснат клавиш, C2 заявка,
token callback — носи `engagement_id`. Това позволява **един клик = целият инцидент**.

## 2. Класове събития

| Домейн | OCSF клас | Източник |
|---|---|---|
| Мрежова активност | 4001 Network Activity | tap, gateway |
| HTTP/DNS/SSH/RDP/SMB | 4002-4014 | tap reconstructors |
| Процеси | 1007 Process Activity | observer (VMI) |
| Файлове | 1001 File System Activity | observer, honey FS |
| Registry | 201x Registry * | observer |
| Автентикация | 3002 Authentication | honeyd, honey AD |
| Модули/инжекции | 1005 Module Activity | observer |
| Открития (findings) | 2004 Detection Finding | brain |
| MIRAGE-специфични | `mirage.*` разширения | tokens, keystrokes, ransomware, crypto keys |

## 3. Съхранение

| Хранилище | Какво | Защо | Retention (дефолт) |
|---|---|---|---|
| **PostgreSQL** | конфигурация, инвентар, кампании, потребители, engagements | транзакционно, релационно | безсрочно |
| **ClickHouse** | всички събития (10^9+ реда) | колонно, компресия 10-30x, sub-second агрегации | 180 дни hot, 2 г. cold |
| **MinIO / S3** | артефакти: pcap, memory dumps, sample-и, RDP видео, PTY записи | обектно, immutable/object-lock | по политика |
| **NATS JetStream** | шина + буфер при загуба на връзка | store-and-forward | 72 ч. |
| **Redis** | live state, rate limits, escalation broker | скорост | ephemeral |

### Обем (оценка)
- 50 примамки, средна активност: ~2-5 GB/ден телеметрия + pcap.
- Активен инцидент с VMI tracing: до 500 MB/час на примамка (syscall поток).
- Adaptive sampling: VMI пише всичко само при активна сесия; иначе — само тригери.

## 4. Форензична цялост

1. Всяко събитие получава `hash = H(prev_hash || canonical_json)`.
2. На всеки N събития / T минути — Merkle root се записва в `mirage-vault`.
3. Опционално: root се timestamp-ва с RFC3161 при външен TSA → доказва момента.
4. Артефактите в MinIO са с **object lock (WORM)** и SHA-256 в манифеста.
5. `Evidence Package` експорт:
   ```
   engagement_01JQ.zip
   ├── manifest.json          (всички хешове, версии, Merkle доказателства)
   ├── chain-of-custody.pdf   (кой, кога, какво е достъпил)
   ├── timeline.json / .csv
   ├── network/*.pcapng, tls-keys.log
   ├── host/*.jsonl           (VMI поток)
   ├── artifacts/*            (sample-и, memdump, ransom note, crypto keys)
   ├── session/*.cast, *.mp4  (терминал, екран)
   └── report.pdf             (автогенериран инцидентен доклад)
   ```
6. Подпис на пакета с ключ на инсталацията (offline root, HSM опционално).

## 5. Export към SIEM/SOAR

| Цел | Формат | Транспорт |
|---|---|---|
| Splunk | OCSF/JSON | HEC |
| Elastic / Wazuh | ECS | Elasticsearch bulk / filebeat |
| Sentinel | ASIM/CEF | Data Collector API |
| QRadar | LEEF | syslog |
| Generic | syslog RFC5424 / JSON webhook | TCP/TLS |
| TheHive / Cortex | Alert API | REST |
| MISP / OpenCTI | STIX 2.1 | REST |
| Velociraptor | hunt artifact | API |

Правило: **alert-ите винаги съдържат линк към engagement-а в MIRAGE UI**, за да не
се налага анализаторът да търси контекста.
