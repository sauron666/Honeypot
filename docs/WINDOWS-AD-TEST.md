# Тест на MIRAGE AD decoy на реална Windows машина

Целта: да покажем, че **нашият** AD honeypot минава за истинско AD пред реалните
офанзивни инструменти — без да инсталираме нищо в системата, без външния скрипт.

Нашият `windows/dc` декой е един `.exe`: емулира Kerberos KDC (с crackable
AS-REP/kerberoast hash-ове), фалшива AD директория по LDAP и NetNTLMv2 улов по
SMB. Не набира навън, не пипа реалния AD, не оставя следи в системата.

## 1. Качване и пускане (на Windows машината)

Или изтегли релийз архива (`make dist` → `mirage-*-windows-amd64.zip`), или
клонирай репото и си вземи `mirage-director.exe` + `profiles/windows-ad-test.yaml`.

В **elevated PowerShell**, в папката с exe-то:

```powershell
# 88 и 389 са свободни на member/standalone сървър. Ако искаш и SMB улов, спри
# услугата Server (иначе закоментирай smb в профила — Kerberos тестът не зависи):
Stop-Service LanmanServer -Force        # по избор, само за SMB

.\mirage-director.exe --config profiles\windows-ad-test.yaml
```

Конзолата тръгва на **http://127.0.0.1:8422**. Отвори я — трябва да видиш декоя
`dcy-dc01` (persona windows/dc) да слуша на 88/389/445.

Пусни на Windows firewall портовете, ако тестваш отвън:

```powershell
New-NetFirewallRule -DisplayName "MIRAGE AD" -Direction Inbound `
  -Protocol TCP -LocalPort 88,389,445 -Action Allow
New-NetFirewallRule -DisplayName "MIRAGE AD UDP" -Direction Inbound `
  -Protocol UDP -LocalPort 88 -Action Allow
```

## 2. AD тестът — реалните инструменти срещу декоя

Домейнът, който декоят представя, е `CORP.LOCAL` (виждаш го по LDAP). Пусни
кое да е от тези срещу машината (от самата нея или от друг Linux/Windows box).
Всяко от тях трябва да „сработи" и да се появи в конзолата на MIRAGE.

**Изброяване на потребители (kerbrute):**
```
kerbrute userenum -d CORP.LOCAL --dc <IP> users.txt
```
Декоят връща различен отговор за съществуващ и несъществуващ акаунт — точно
както истински KDC. В конзолата: събития "user enumeration".

**AS-REP roast (Impacket GetNPUsers):**
```
GetNPUsers.py CORP.LOCAL/ -dc-ip <IP> -no-pass -usersfile users.txt
```
`svc_legacy` има изключен pre-auth → връща `$krb5asrep$23$...` hash. Той се
чупи с hashcat (mode 18200) до планирана парола. Това е доказано независимо в
`internal/honeyd/svc_kerberos_test.go`.

**Kerberoast (Impacket GetUserSPNs):**
```
GetUserSPNs.py CORP.LOCAL/<user>:<pass> -dc-ip <IP> -request
```
Service акаунтите (svc_sql, svc_backup, svc_iis) имат SPN → връщат
`$krb5tgs$23$...` (hashcat mode 13100), също crackable.

**LDAP изброяване (ldapsearch / BloodHound):**
```
ldapsearch -x -H ldap://<IP>:389 -b "DC=CORP,DC=LOCAL" "(objectClass=user)"
```
Вижда потребители, service акаунти със SPN, привилегировани групи.

## 3. Какво да гледаш

В конзолата (таб Engagements) всяка от тези атаки се стича в **един engagement**
с risk score, и всяко подхвърлено име/парола влиза в tamper-evident веригата.
Провери я по всяко време:

```powershell
.\miragectl.exe verify --file C:\ProgramData\MIRAGE\ad-test\evidence.jsonl
```

Ключовото: паролите в раздадените hash-ове са **crackable по дизайн** (форматът,
който хората избират), различни за всяко внедряване. Кракът не отключва нищо —
но watcher-ът свързва офлайн крака със следващото място, където паролата се появи.

## 4. Спиране

Ctrl+C на director-а. Ако си спрял LanmanServer:
```powershell
Start-Service LanmanServer
```
Нищо не е инсталирано — няма какво да се чисти освен `C:\ProgramData\MIRAGE`.
