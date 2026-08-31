# 10 — Доказателства и Vault

Deception произвежда доказателства, не логове. За да струват в съд или пред
одитор, трябва да са неподправяеми **и** проверими от трета страна. MIRAGE прави
и двете: append-only hash chain + ed25519 подпис + RFC 3161 timestamp.

## Слой 1 — append-only hash chain

Всяко събитие се зашива към предишното чрез хеш. Събитие веднъж записано не се
променя. `store.Verify` открива промяна, изтриване **и** разместване.

От конзолата: секция **Evidence Chain** → **Verify** прави replay на целия
chain и казва VERIFIED или точно кое събитие е пипнато.

От CLI:

```bash
./bin/miragectl verify --file data/evidence.jsonl
```

Тънкост, платена на живо: крах/kill по средата на append оставя частичен
последен ред. `store.replay` го отрязва (torn tail) и продължава от последното
трайно събитие. Но повреда в **средата** на файла (пълен ред, който не декодира)
пак гърми — това е подправяне. `RecoveredBytes()` докладва отрязаното.

## Слой 2 — подпис + timestamp (vault)

Chain-ът доказва „нищо не е пипано отвътре". Vault добавя две неща отвън:

- **ed25519 seal** на chain head → „това е от това внедряване".
- **RFC 3161 timestamp** (опционален) → „съществуваше тогава".

```bash
# подпечатай (ключът се създава, ако липсва)
./bin/miragectl vault seal \
  -file data/evidence.jsonl \
  -key data/vault.key \
  -tenant acme -site sofia \
  -tsa https://freetsa.org/tsr        # опционално

# провери печата (и по избор — срещу текущия файл)
./bin/miragectl vault verify \
  -seal data/evidence.jsonl.seal.json \
  -file data/evidence.jsonl
```

Tamper на файла проваля `vault verify` — подписът е върху head hash-а, а head
hash-ът зависи от всяко събитие.

> Подписването е **CLI операция**, не GUI бутон — нарочно. Печатът пази частния
> ключ; операторът го управлява явно, вместо да го излага през уеб конзола.

## Работен процес за инцидент

1. Инцидентът приключва → затвори engagement-а.
2. `miragectl verify` — увери се, че веригата е цяла.
3. `miragectl vault seal --tsa …` — подпечатай с timestamp.
4. Предай `.seal.json` + evidence файла на разследващия. Той проверява с
   `vault verify` и публичния fingerprint, без да ти вярва на дума.

## Какво следва

- [Compliance и Export](11-compliance-export.md) — същите доказателства, изнесени
  към SIEM/threat intel и мапнати към регулаторни контроли.
