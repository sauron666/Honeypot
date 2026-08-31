# 11 — Compliance и Export

Двете неща, които купувачът иска освен детекция: „покрий ми регулацията" и
„влей ми го в SIEM-а". MIRAGE прави и двете от способностите на живото
внедряване, не от чеклист на хартия.

## Compliance — покритие срещу регулации

`compliance.Audit` инспектира какво реално предоставя внедряването (hash chain,
декои, engagement-и, forge, VM ферма, overlay…) и го мапва към контроли на
**NIS2, DORA, ISO 27001:2022, PCI DSS 4.0, SOC 2, IEC 62443**.

От конзолата: секция **Compliance** → избери рамка (pill-овете). Виждаш
процент покритие и таблица контрол-по-контрол със статус satisfied/gap и
доказателството зад всеки.

От CLI:

```bash
./bin/miragectl compliance -config profiles/p0-box.yaml
```

Важно: способност→контрол мапингът е честен. Ако нямаш VM ферма, контролите,
които я изискват, са `gap`, не „зелено защото сме платили".

## Export — към SIEM и threat intel

От recorded доказателства към стандартни формати:

```bash
# STIX 2.1 bundle (MISP/OpenCTI)
./bin/miragectl export -file data/evidence.jsonl -format stix > iocs.stix.json

# TheHive alert
./bin/miragectl export -file data/evidence.jsonl -format thehive > alert.json

# дедупликиран IOC списък (за blocklist/hunt)
./bin/miragectl export -file data/evidence.jsonl -format iocs > iocs.txt
```

Per-engagement износът е и в GUI: секция **Detection Rules** и бутоните
STIX/report на всеки engagement ([04](04-detections.md)).

## Sink-ове в реално време

Освен ad-hoc износ, всяко събитие може да тече на живо към SIEM чрез sink
драйвер (конфигуриран в манифеста): `stdout`, `file`, `webhook`, `syslog`,
`elastic` (ECS), `splunk` (HEC). Два+ имплементации на категория — ADR-008.

## Сдържаност в детекцията

`forge` **отказва** да прави правило от `ls` или от нормален browser user agent
и публикува защо. Правило, което гърми на нормална активност, изключва целия
feed — затова MIRAGE предпочита да не произведе правило, отколкото да произведе
шумно.

## Целият кръг

1. Атака → engagement → tamper-evident доказателство.
2. `vault seal` → юридически проверимо ([10](10-evidence-vault.md)).
3. `export` → threat intel / SIEM.
4. `compliance` → регулаторен доклад.
5. `forge` → детекции, които ловят следващия път.

Един инцидент, изстискан докрай.
