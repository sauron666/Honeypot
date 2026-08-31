# 08 — AD декой + Kerberos

Active Directory е целта №1 във всяка сериозна атака. MIRAGE вдига фалшив домейн
контролер с **истински KDC** — не имитация на банер, а работещ Kerberos, срещу
който реалните инструменти (Rubeus, impacket, hashcat) работят и се хващат.

Персона: `windows/dc`. Услуги: `kerberos`, `ldap`, `smb`.

## Какво хваща

- **Enumeration** — обхождане на потребители по LDAP/Kerberos.
- **Password spraying** — един пароль срещу много акаунти.
- **AS-REP roasting** — акаунти без preauth; blob-ът е истински RC4-HMAC.
- **Kerberoasting** — TGS за service акаунт; също crackable.
- **SMB** — улавя NetNTLMv2 при опит за автентикация.

## Защо паролите трябва да са crackable

AS-REP/TGS blob-овете са истински RC4-HMAC над истински DER, с NT hash на
**планирана парола с формата, който хората избират**. Ако паролата е случайна,
hashcat не я намира и атакуващият разбира, че акаунтът е фалшив.

Стойността е в **reuse-а**: watcher-ът свързва офлайн крака (hashcat намери
паролата) с онлайн опита (същата парола срещу друг декой). Това е сигнал, който
нищо легитимно не произвежда.

## Един каталог, два изгледа

LDAP и Kerberos четат от **един и същ** `buildHoneyDirectory`. Ако услуга се
вижда по LDAP, но не се roast-ва по Kerberos, атакуващият е намерил шева.
`TestKerberosBaitAgreesWithWhatLDAPAdvertises` пази точно това.

## Kerberos е TCP и UDP

Клиентите пробват UDP и падат към TCP, когато отговорът не се събира. KDC-то се
декларира два пъти на порт 88. По UDP всеки съществен отговор е
`KRB5KRB_ERR_RESPONSE_TOO_BIG` (без e-text — иначе е amplification), точно както
връща истински KDC.

## Кои акаунти са примамка (в `windows/dc` персоната)

Realm-ът е **`CORP.LOCAL`** (uppercase на домейна). Точните цели:

| Акаунт | Тип примамка | Как се напада |
|---|---|---|
| `svc_legacy` | **AS-REP roastable** (pre-auth изключен) | AS-REQ без pre-auth → crackable AS-REP |
| `svc_sql`, `svc_backup`, `svc_iis` | **kerberoastable** (имат SPN) | TGS-REQ с RC4 → crackable service ticket |
| `m.petrova`, `g.ivanov`, `e.dimitrova`, `n.stoyanov`, `i.kolev` | обикновени (pre-auth ВКЛ) | само spray/guess — всеки опит се записва |

svc_sql/svc_backup **изискват** pre-auth (AS-REP roast срещу тях връща
`KDC_ERR_PREAUTH_REQUIRED` — точно като истински домейн); те се roast-ват през
**Kerberoast**, не AS-REP. Единственият AS-REP roastable е `svc_legacy`.

## Тест с реални инструменти

> **Портове:** impacket/Rubeus предполагат стандартните **88** (Kerberos) и
> **389** (LDAP). p0 профилът кара на 8888/3389 (без root). За жив тест или
> вдигни услугите на 88/389 (`CAP_NET_BIND_SERVICE`), или форуърдни:
> `socat TCP-LISTEN:88,fork,reuseaddr TCP:127.0.0.1:8888` (и 389→3389).

```bash
# AS-REP roast — таргетирай svc_legacy, realm CORP.LOCAL
echo svc_legacy | GetNPUsers.py CORP.LOCAL/ -dc-ip 127.0.0.1 -no-pass \
  -usersfile /dev/stdin -format hashcat

# Kerberoast — svc_sql/svc_backup/svc_iis имат SPN
GetUserSPNs.py CORP.LOCAL/ -dc-ip 127.0.0.1 -no-preauth svc_legacy -request

# crack — паролата се намира, защото е crackable by design
hashcat -m 18200 asrep.hash rockyou.txt    # AS-REP
hashcat -m 13100 tgs.hash   rockyou.txt    # kerberoast
```

Гледай конзолата: всеки се появява като engagement с ATT&CK мапинг
(T1558.004 AS-REP roasting, T1558.003 Kerberoasting, T1110 spraying…). Стойността
е в **reuse-а**: watcher-ът свързва офлайн крака (hashcat намери паролата) с
онлайн опит със същата парола другаде.

## Допълнителни примамки в персоната

`windows/dc` носи и ADCS, LAPS и kerberoast/AS-REP примамки — типичните цели
след първоначален достъп до домейна.

Пълният жив тест е в `docs/WINDOWS-AD-TEST.md`.

## Какво следва

- [Детекции за SIEM](04-detections.md) — направи Sigma/Suricata от AD атаката.
- [Доказателства и Vault](10-evidence-vault.md) — подпечатай за разследване.
