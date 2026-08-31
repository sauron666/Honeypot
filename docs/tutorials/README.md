# MIRAGE — Туториали

Практични, стъпка-по-стъпка ръководства. За разлика от `docs/00`–`docs/11`
(които са планът и архитектурата), тук всяко нещо е „как да го направя".

Всичко се управлява или от **операторската конзола** (GUI на
`http://127.0.0.1:8422`), или от **`miragectl`**. Всеки туториал показва и двете,
където има смисъл.

| # | Туториал | За какво |
|---|---|---|
| 01 | [Бърз старт](01-quickstart.md) | Вдигни MIRAGE за 10 минути, атакувай го, виж конзолата |
| 02 | [Операторската конзола](02-operator-console.md) | Обиколка на GUI-то — всяка секция и какво можеш да правиш |
| 03 | [Honeytokens](03-honeytokens.md) | Издай примамки-токени, подхвърли ги, виж как гърмят |
| 04 | [Детекции за SIEM](04-detections.md) | Превърни engagement в Sigma/Suricata/YARA/STIX |
| 05 | [Пълни VM примамки](05-full-vm-decoys.md) | Истински VM декои на Proxmox: containment, burn, revert |
| 06 | [VMI наблюдение](06-vmi-observer.md) | Agentless наблюдение отвътре (Xen + DRAKVUF, Windows guest) |
| 07 | [Overlay режим](07-overlay-mode.md) | Проектирай декои в чужд сегмент без промяна на мрежата |
| 08 | [AD декой + Kerberos](08-ad-decoy.md) | Фалшива Active Directory: roast/spray, тест с реални инструменти |
| 09 | [Breadcrumbs](09-breadcrumbs.md) | Подхвърли следи на реални машини, водещи в honeynet-а |
| 10 | [Доказателства и Vault](10-evidence-vault.md) | Tamper-evident верига + подписи + RFC 3161 timestamp |
| 11 | [Compliance и Export](11-compliance-export.md) | NIS2/DORA доклади и threat-intel износ |
| 12 | [Ransomware trap](12-ransomware-trap.md) | Защита от криптори на всеки хипервайзор (FUSE tarpit + snapshot) |
| 13 | [Библиотека с образи](13-image-library.md) | Внеси ISO/OVA/qcow2, тагвай easy/med/hard/insane, санирай (махни флагове) |

## Първите пет минути

```bash
make build
./bin/miragectl doctor --config profiles/p0-box.yaml   # проверка преди старт
./bin/mirage-director --config profiles/p0-box.yaml     # конзола: http://127.0.0.1:8422
```
