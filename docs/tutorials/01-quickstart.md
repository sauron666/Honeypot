# 01 — Бърз старт

Целта: работещ honeypot за 10 минути, без база данни, без Docker, без root.

## 1. Build

Нужен е само Go 1.24+.

```bash
make build
# -> bin/mirage-director, miragectl, mirage-presence, mirage-breadcrumbs
```

Или си вземи готов бинар от релийз архива (`make dist` прави за Windows/Linux/macOS).

## 2. Проверка преди старт

```bash
./bin/miragectl doctor --config profiles/p0-box.yaml
```

`doctor` хваща грешките, които иначе би открил по време на инцидент: невалиден
конфиг, недостижим alert sink, липсваща изолация. Оправи каквото маркира.

## 3. Старт

```bash
./bin/mirage-director --config profiles/p0-box.yaml
```

Това вдига шест примамки с последователни идентичности (уеб сървър, база данни,
NAS, файлов сървър, домейн контролер, PLC) на неприлежни портове. Отвори
операторската конзола: **http://127.0.0.1:8422**

## 4. Атакувай го

От друг терминал:

```bash
curl http://127.0.0.1:8080/.env                    # scanner path — веднага е събитие
ssh -p 2222 root@127.0.0.1                          # паролата "toor" минава
redis-cli -p 6380 CONFIG SET dir /var/spool/cron    # класическата Redis верига
mysql -h 127.0.0.1 -P 3307 -u dba -pdba123          # подхвърлената парола минава
```

Гледай конзолата: всяко докосване се появява, свързва се в **engagement** (една
история за един атакуващ) с risk score, и се зашива в tamper-evident веригата.

## 5. Провери доказателствата

```bash
./bin/miragectl verify --file data/evidence.jsonl
```

Ако някой е пипал файла, `verify` го открива и казва точно кое събитие.

## Какво следва

- [Операторската конзола](02-operator-console.md) — управлявай всичко от GUI.
- [Honeytokens](03-honeytokens.md) — примамки без инфраструктура.
- [Детекции за SIEM](04-detections.md) — превърни атаката в правила.
