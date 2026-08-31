# 04 — Детекции за SIEM

Най-силната част: примамката **пише детекциите за реалната ти мрежа**. От един
записан engagement MIRAGE генерира Sigma, Suricata, YARA и STIX — готови за
твоя SIEM/IDS.

## От конзолата

1. Отвори **Engagements**, избери един (подреден по risk).
2. Мини в **Detection Rules** (forge) секцията.
3. Свалиш: `sigma`, `suricata`, `yara`, `stix`, или целия `report`.

## От CLI

```bash
# от най-високорисковия engagement във файла
./bin/miragectl forge --file data/evidence.jsonl --out ./detections

# конкретен engagement
./bin/miragectl forge --file data/evidence.jsonl --engagement <id> --out ./detections
```

Изходът:
```
detections/report.md          # инцидентен доклад
detections/sigma-*.yml        # за SIEM (Splunk, Elastic, Sentinel…)
detections/suricata-*.rules   # за IDS/IPS
detections/captured-*.yar     # YARA за подхвърлени payload-и
detections/stix-*.json        # STIX 2.1 bundle
detections/iocs-*.tsv         # дедупликиран IOC списък
```

## Защо е сдържано

`forge` **отказва** да прави правило от `ls` или от нормален browser user agent —
и публикува защо. Детекция от шум е по-лоша от липса на детекция: наводнява
SOC-а. Затова всяко правило е от нещо, което няма легитимна причина да се случи
на декой.

## Износ към threat intel

За MISP/OpenCTI/TheHive виж [Compliance и Export](11-compliance-export.md):

```bash
./bin/miragectl export --file data/evidence.jsonl --format stix    # STIX 2.1
./bin/miragectl export --file data/evidence.jsonl --format thehive # TheHive alert
./bin/miragectl export --file data/evidence.jsonl --format iocs    # дедуп IOC списък
```
