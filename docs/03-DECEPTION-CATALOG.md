# 03 — Каталог на измамата

## 1. Класове примамки

### 1.1 Мрежови примамки (decoys)
| Клас | Примери | Ниво | Цел (ATT&CK) |
|---|---|---|---|
| Работни станции | Win10/11 domain-joined, "счетоводство-07" | L3/L4 | Discovery, Lateral Movement |
| Сървъри | Win Server (File/Print/SQL), Debian (web/app/db) | L3/L4 | T1021, T1078, T1210 |
| Файлов сървър | SMB share с "заплати", "договори", "backup" | L4 | T1039, T1486 (ransomware) |
| Домейн инфраструктура | honey DC, ADCS, honey CA template | L3 | T1558, T1649, T1003.006 |
| Мрежово оборудване | суич/рутер/firewall web UI, VPN портал | L1/L2 | T1133, T1190 |
| Приложни | Jenkins, GitLab, Confluence, Exchange/OWA, Citrix | L2 | T1190 |
| Инфраструктурни API | Docker socket, K8s API, vCenter, Proxmox UI | L2 | T1610, T1613 |
| Backup системи | Veeam/Bacula UI, NAS (Synology/QNAP) | L2/L3 | T1490 — ransomware винаги ги търси |
| OT/ICS | Modbus PLC, S7-1200, HMI, DNP3 RTU, BACnet | L1/L2 | ICS матрицата |
| IoT | камери, принтери, IPMI/iDRAC | L1 | T1200, ботнети |
| Cloud | фалшив S3 bucket, fake IAM endpoint, Azure app | L1 | Cloud матрицата |

### 1.2 Honeytokens (без инфраструктура)
- **Креденшъли**: AWS/Azure/GCP ключове, DB connection strings, API токени,
  service account пароли, SSH ключове.
- **Файлове**: Office/PDF с remote resource, `.lnk`, `.exe` canary, ZIP bombs (само
  като детектор, не като защита), `.kdbx` с token вътре.
- **Идентичност**: AD акаунт с SPN (kerberoast капан), AS-REP-roastable акаунт,
  акаунт в "Domain Admins"-подобна група, компютърен акаунт, ADCS шаблон,
  който **изглежда** ESC1-уязвим → всяка заявка = alert.
- **Данни**: ред в БД, запис в CRM, email адрес, телефон, IBAN — за detection на
  data exfil и за проследяване къде изтича.
- **Мрежови**: DNS token, canary URL, WPAD/LLMNR/mDNS отговор, SMB share име.
- **Cloud/SaaS**: Slack/GitHub/GitLab token, Office365 app registration.

### 1.3 Breadcrumbs (в реалната мрежа — пътят към примамката)
Атакуващият трябва да **намери** honeynet-а. Breadcrumbs са картата.

| Носител | Съдържание | Задейства |
|---|---|---|
| RDP история / `.rdp` файлове | адрес на honey сървър | T1021.001 |
| Credential Manager | honey домейн акаунт | T1555.004 |
| Browser saved passwords | honey web app | T1555.003 |
| `.ssh/config`, `known_hosts` | honey Linux сървъри | T1021.004 |
| Mapped drives / `net use` | honey файлов сървър | T1039 |
| `.aws/credentials`, `.kube/config` | honeytoken ключове | T1552.001 |
| PowerShell/bash history | команди сочещи към примамки | T1552.003 |
| hosts файл / DNS suffix | резолюция на honey имена | Discovery |
| Планирана задача / скрипт | "backup към \\\\HONEY-NAS01" | Discovery |
| LSASS-подобни артефакти | fake кеширани креденшъли (само в memory-safe вид) | T1003 |

**Правило за реализъм:** breadcrumb-ите трябва да са в сегмента и с конвенцията на
реалната среда. `mirage-brain` профилира реалната мрежа (пасивно, през Zeek/AD read-only)
и генерира именуване, което не изпъква.

## 2. Anti-fingerprinting (как не ни хващат)

### 2.1 Виртуализация
- CPUID hypervisor bit скрит; realistic CPU model.
- SMBIOS/DMI: реален вендор/модел/сериен номер (Dell OptiPlex, HP ProLiant, Lenovo).
- Дискови модели: реални низове (`SAMSUNG MZ7LH...`), не `QEMU HARDDISK`.
- Мрежови адаптери: e1000e/Intel вместо очевидно virtio, където има значение;
  **MAC OUI съвпадащ с реалния флот**.
- TPM 2.0 присъства; UEFI с реалистичен BIOS.
- Timing: без изкуствени забавяния; RTC/TSC консистентни.

### 2.2 Операционна система
- Реален OS (не емулация) → всяка команда се държи истински.
- **Без агент** → празен process list от гледна точка на защита.
- Uptime, patch level, инсталиран софтуер, AV агент (реален, но в наблюдателен режим) —
  всичко като реален корпоративен образ.
- Event log с месеци история (Life Engine), не 200 записа отпреди 3 дни.
- Реални потребителски профили с документи, downloads, recent items.

### 2.3 Мрежа
- Хостът генерира фонов трафик (DHCP renew, WSUS, NTP, AV update, LDAP, DNS).
- Отговаря на inventory скенери консистентно (SNMP, WMI, SSH banner).
- Няма характерен "всички портове отворени" патерн — портовият профил съвпада с ролята.
- DHCP fingerprint (option 55 ред) съвпада с реалния OS.

### 2.4 Услуги (емулирани L1/L2)
- Не се използват публично известни honeypot кодови бази с дефолтни артефакти
  (Cowrie SSH ключове, стандартни банери, известни отговорни грешки).
- Per-deploy рандомизация: host keys, cert-и, банер версии, error strings,
  реда на HTTP хедърите, TCP опции.
- Отговорите се валидират срещу **реални** реализации (regression corpus).

### 2.5 Honeypot-detection тестове в CI
Продуктът се тества автоматично срещу известни техники за откриване:
- `honeypot-detector`-подобни скриптове, Nmap NSE, Shodan Honeyscore логика
- ръчен red-team тест всяко тримесечие
- **Критерий за приемане:** обучен оператор с 30 мин. на машината не може да заключи
  с увереност, че е примамка.

## 3. Ransomware Trap Engine (★)

### 3.1 Стръв
- Honey file server с **генерирана в движение** файлова система (FUSE): милиони файлове,
  безкрайна дълбочина, реални размери — на диска заема мегабайти.
- Canary файлове с имена, които сортират **първи** (`!!!_backup_2024.xlsx`,
  `AAA_zaplati.xlsx`) — повечето encryptor-и обхождат азбучно.
- Реални Office/PDF/ZIP файлове (правилни magic bytes) — не празни.
- Shadow copies, backup папки, `.bak` — това, което ransomware търси първо.

### 3.2 Детекция (многослойна, независими източници)
| Слой | Сигнал |
|---|---|
| SMB сървър (наш) | скорост на write/rename, ентропия на записваните блокове, загуба на magic bytes, extension churn |
| VMI | `BCryptGenerateSymmetricKey`, `CryptEncrypt`, масов `SetFileInformation` rename, `vssadmin delete shadows`, `bcdedit` |
| Файлова система | докосване на canary в неправилен ред/скорост |
| Мрежа | опит за ключов обмен с C2, DNS към known families |
| Поведение | изтриване на shadow copies, спиране на услуги, `wbadmin`, `wevtutil cl` |

### 3.3 Отговор (автоматичен, конфигурируем)
1. **Ключов улов**: VMI hook върху crypto API → dump на симетричния ключ **преди**
   да бъде занулен + IV + режим. Съхранява се в vault. При много семейства това
   дава реален decryptor за реалните жертви в организацията.
2. **Tarpit**: FUSE latency скача експоненциално → encryptor-ът се влачи с часове,
   докато SOC-ът реагира. (Само в примамката — нулев риск за прод.)
3. **Улов на sample**: бинарът се копира от паметта и от диска, ransom note се записва,
   affiliate ID/BTC адрес се извличат.
4. **Snapshot**: пълен memory + disk snapshot преди revert.
5. **Разпространение на IOC**: hash/IOC веднага към EDR/SIEM за блокиране в реалната мрежа.
6. **Revert** на примамката < 15s и продължаване на наблюдението (нов клонинг),
   ако актьорът е още активен.

## 4. Identity Deception (AD / ADCS / IdP)
- **Honey SPN акаунт**: изглежда като service account с RC4 и слаба парола →
  всяко Kerberoast заявяване = alert (T1558.003).
- **AS-REP roastable акаунт** (без preauth) → T1558.004.
- **DCSync canary**: акаунт с привидни репликационни права; всяка `DRSGetNCChanges`
  заявка към него = alert (T1003.006).
- **ADCS**: шаблон, който изглежда ESC1-уязвим (`ENROLLEE_SUPPLIES_SUBJECT` + client auth);
  издаването е позволено, но сертификатът е **honeytoken** — всяко използване алармира.
- **Honey GPO / SYSVOL**: скрипт с "парола" в него (класическа находка на всеки
  оператор с `Get-GPPPassword`).
- **LAPS honey**: обект, който изглежда че съдържа local admin парола.
- **Deceptive LDAP отговори**: `mirage-honeyd` LDAP слой връща допълнителни фалшиви
  обекти на неоторизирани enum заявки (само за източници извън allowlist).

> Важно: всички тези обекти живеят в **отделна honey гора / отделен OU без trust към
> продукцията**, или като read-only проекция. Никога не се създава реален път за ескалация.

### 4.1 Същото, но за cloud идентичност (`IdentityDriver`)
Атаките днес често започват в IdP-то, не в мрежата. Еквивалентите:

| AD свят | Cloud/SaaS еквивалент | Задейства |
|---|---|---|
| Honey SPN акаунт | honey потребител в Entra ID/Okta, който никога не логва | password spraying, MFA fatigue |
| Honey админ група | honey роля с "прекомерни" права | privilege enumeration |
| ADCS honey шаблон | honey OAuth приложение с широк consent | consent phishing |
| Honey GPO с "парола" | honey secret в Vault/Key Vault с audit tripwire | T1552 |
| Honey SYSVOL файл | honey документ в SharePoint/Drive с воден знак | data staging |
| Honey LAPS обект | honey Conditional Access изключение | policy tampering |

Детекцията често не изисква **никаква** инфраструктура — само четене на audit
логовете на доставчика. Това е най-евтината deception, която съществува.

## 5. Нови повърхности

Пълно описание: `docs/11-IDEAS.md`. Резюме на класовете:

| Повърхност | Примамки | Защо |
|---|---|---|
| **Supply chain / DevOps** | dependency-confusion канари (вътрешни имена на пакети, регистрирани публично), honey CI runner, honey repo с "тайни", honey artifact registry | компрометирането на pipeline е сред най-скъпите инциденти, а детекцията е почти нулева |
| **Kubernetes** | honey namespace, honey ServiceAccount, "забравен" secret в etcd, привилегирован под | всеки достъп до тях е недвусмислен |
| **AI агенти / MCP** ★ | honey MCP сървър, prompt-injection канари в документи, honey LLM API ключове, маркиран RAG корпус | нова, бързо растяща повърхност; засича и вражески агенти, и shadow AI |
| **Email / BEC** | honey мейлбокси в публични корпуси, фалшива финансова идентичност на сайта | улавя кампании седмици преди да ударят реални хора |
| **Insider threat** | honey документи, видими само на определена група; honey БД записи | достъпът няма легитимно обяснение (изисква съгласуване с DPO/съвет на работниците) |
| **Wireless / BYOD** | honey SSID, honey BLE, honey принтер по mDNS | евтино, добра демонстрация |

## 6. Разполагане: къде точно да бъдат примамките

Разхвърлянето на примамки "по 5 на VLAN" е лотария. `mirage-graph`
(`docs/02`) изчислява графа на реалната среда и поставя примамките **по пътищата на
атаката** — там, където реалистичните маршрути до коронните бижута минават.
Измерима цел: *≥ 80% от пътищата до Domain Admin пресичат примамка на ≤ 3 стъпки.*

Допълва се от `mirage-jit` (реактивни примамки: атакуващият търси MSSQL → появява се
MSSQL) и от `mirage-assure` (непрекъснат тест доколко примамките са разпознаваеми).
