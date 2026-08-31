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

## Тест с реални инструменти

```bash
# AS-REP roast (impacket)
GetNPUsers.py corp.local/ -dc-ip 127.0.0.1 -usersfile users.txt -no-pass

# Kerberoast (Rubeus/impacket)
GetUserSPNs.py corp.local/decoyuser:pass -dc-ip 127.0.0.1 -request

# crack-ни blob-а — паролата се намира, защото е crackable by design
hashcat -m 18200 asrep.hash rockyou.txt
```

Гледай конзолата: всеки от тези се появява като engagement с ATT&CK мапинг
(T1558 Kerberoasting, T1110 spraying…).

## Допълнителни примамки в персоната

`windows/dc` носи и ADCS, LAPS и kerberoast/AS-REP примамки — типичните цели
след първоначален достъп до домейна.

Пълният жив тест е в `docs/WINDOWS-AD-TEST.md`.

## Какво следва

- [Детекции за SIEM](04-detections.md) — направи Sigma/Suricata от AD атаката.
- [Доказателства и Vault](10-evidence-vault.md) — подпечатай за разследване.
