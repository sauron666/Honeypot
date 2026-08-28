# Профили на внедряване

Профилът е декларативното описание на едно внедряване: кои примамки, с какви
персони, на кои портове, къде отиват алармите и кои драйвери стоят отдолу.
Един и същ файл работи, независимо дали примамките живеят в процеса, в
контейнери или на хипервайзор — сменя се само `drivers.compute`.

| Файл | Профил | За кого |
|---|---|---|
| `p0-box.yaml` | P0 — honeypot в кутия | първи досег, SMB, Community изданието |
| `p3-mssp-overlay.yaml` | P3 — MSSP / overlay | примамки в чужд сегмент, без промяна на мрежата |
| `homelab-proxmox-opnsense.yaml` | P7 — домашна лаборатория | Proxmox + OPNsense + AD (референтната среда) |

Пълното описание на седемте профила: `docs/06-DEPLOYMENT-PROFILES.md`.

## Бърз старт

```bash
make build
./bin/miragectl doctor --config profiles/p0-box.yaml
./bin/mirage-director --config profiles/p0-box.yaml
# конзолата: http://127.0.0.1:8422
```

## Портове

**Никога не пускай honeypot като root.** Профилите използват непривилегировани
портове; за да представиш истинските портове, пренасочи ги на защитната стена:

```bash
# Linux, nftables
nft add rule inet nat prerouting tcp dport 22   redirect to :2222
nft add rule inet nat prerouting tcp dport 80   redirect to :8080
nft add rule inet nat prerouting tcp dport 21   redirect to :2121
nft add rule inet nat prerouting tcp dport 23   redirect to :2323
nft add rule inet nat prerouting tcp dport 6379 redirect to :6380
nft add rule inet nat prerouting tcp dport 3306 redirect to :3307
```

На OPNsense същото се прави с port forward правило към адреса на MIRAGE.

## Overlay режим (профил P3)

Presence Agent-ът поема неизползвани адреси в чужд сегмент и тунелира към хъба.
Адресите трябва вече да съществуват на хоста:

```bash
ip addr add 10.20.5.240/24 dev eth0
ip addr add 10.20.5.241/24 dev eth0

MIRAGE_PRESENCE_TOKEN=... ./bin/mirage-presence \
  --hub mirage.example:8443 --id floor-3 \
  --addresses 10.20.5.240,10.20.5.241 \
  --services ssh:22,http:80,smb:445
```

Токенът се подава през променлива на средата, не като флаг — флаговете се
виждат в списъка с процеси.

Правила (ADR-009):
- агентът винаги набира навън; хъбът никога не набира навътре;
- хъбът решава кои услуги може да носи агентът, не агентът;
- при паднал тунел агентът не обслужва нищо — примамка, която отговаря,
  докато нищо не записва, е по-лоша от затворен порт.

## Задължителни проверки преди продукция

1. `api.listen` е на управляваща мрежа, **не** в сегмента на примамките.
2. Ако `api.listen` не е loopback — задай `api.token`.
3. Сегментът на примамките няма маршрут към продукцията (`docs/04 §2`).
4. `data_dir` е на дял с достатъчно място; доказателствата растат.
5. `deploy.seed` във `data_dir` се пази — той прави примамките стабилни между
   рестарти. Загубиш ли го, всички hostname-и и подхвърлени тайни се сменят.
