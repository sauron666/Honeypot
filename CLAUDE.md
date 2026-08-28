# MIRAGE — работно състояние и конвенции

> Този файл се чете автоматично в началото на всяка сесия. Той е паметта на
> проекта: къде сме, какво не бива да се нарушава, какво следва. Ако нещо в
> него не отговаря на кода — кодът е прав, файлът се обновява.

**Какво е:** платформа за deception (honeypot/honeynet). Пълният план е в
`docs/`; този файл е оперативното резюме.

**Клон за работа:** `claude/honeypot-software-plan-c9txsh`. Пуш след всеки
завършен етап.

---

## 1. Състояние към последния commit

Работещ продукт в профил P0 („honeypot в кутия"): един бинар вдига примамки,
записва всичко в tamper-evident chain, стичва го в engagement-и, вдига аларми
и го показва в операторска конзола. ~24 500 реда Go, ~6 000 от тях тестове.

```bash
make build
./bin/miragectl doctor --config profiles/p0-box.yaml
./bin/mirage-director --config profiles/p0-box.yaml   # конзола: 127.0.0.1:8422
```

### Пакети

| Пакет | Какво прави |
|---|---|
| `internal/event` | OCSF събитие, ULID, канонична сериализация, **append-only hash chain** |
| `internal/store` | append-only JSONL evidence, resume след рестарт, стрийм проверка |
| `internal/bus` | шина, NATS-съвместим subject matching; `Close()` изчаква handler-ите |
| `internal/drivers` | осемте абстракции + registry с capabilities (ADR-008) |
| `internal/drivers/compute` | `inproc`, `podman`, `libvirt` |
| `internal/drivers/sink` | `stdout`, `file`, `webhook`, `syslog`, `elastic` (ECS), `splunk` (HEC) |
| `internal/driverset` | регистрация на вградените драйвери (отделен пакет заради import cycle) |
| `internal/honeyd` | фермата: 15 протокола, персони, виртуална ФС, shell, reconcile |
| `internal/engagement` | стичане на събития в една история; `FromEvents` за офлайн възстановяване |
| `internal/alert` | праг по severity, дедупликация, линк към engagement, synthetic маркер |
| `internal/tokens` | honeytokens: 8 типа, callback, watcher, .docx генератор |
| `internal/ransomware` | шест сигнала за криптор, tarpit, извличане на контакти от бележката |
| `internal/forge` | генериране на Sigma/Suricata/YARA/STIX + инцидентен доклад |
| `internal/assure` | самотест на веригата + **Detectability Score** (fingerprint) |
| `internal/config` | YAML манифест, валидация, `plan` диф, immutable настройки |
| `internal/app` | сглобяването на едно място (бинарът и e2e тестовете ползват него) |
| `internal/presence` | overlay: хъб + Presence Agent, тунел с мултиплексиране, взаимен TLS + собствен CA (`ca.go`) |
| `internal/farm` | пълни VM примамки: provisioner, containment gate, baseline, revert, burn |
| `internal/drivers/fabric` | `nftables` (налага + чете правилата), `probe` (тества реалната достижимост) |
| `internal/api` | REST + вградена конзола (`internal/api/web/`) |
| `cmd/mirage-director`, `cmd/miragectl`, `cmd/mirage-presence` | бинарите |

### Протоколи (`internal/honeyd/svc_*.go`)

`ssh` (истински, x/crypto), `ldap` (фалшива AD), `kerberos` (истински KDC:
enumeration, spraying, AS-REP roast и kerberoast с crackable RC4-HMAC hash),
`smb` (NetNTLMv2 улов), `http`, `telnet`, `ftp` (+ransomware engine), `redis`,
`mysql` (верифицира подхвърлена парола от скрамбъла), `mssql` (възстановява
паролата в чист текст), `vnc`, `smtp`, `snmp` (UDP), `modbus` (ICS), `tokens`
(callback приемник), `generic`.

### Персони (`internal/honeyd/persona_*.go`)

`linux/web`, `linux/db`, `linux/backup`, `linux/fileserver` (генериран дял с
canary файлове), `windows/dc` (AD с kerberoast/AS-REP/ADCS/LAPS примамки).

---

## 2. Инварианти — не се нарушават

1. **Containment преди функционалност.** Примамка никога не набира навън и
   никога не изпълнява нищо. `wget`/`ssh`/`nc` в shell-а връщат правдоподобен
   отказ + IOC събитие. UDP отговорите са ограничени срещу amplification
   (виж `amplificationSafe` в `server.go`). Има тестове точно за това.
2. **Нула вендори в ядрото** (ADR-008). Вендорски пакет само в
   `internal/drivers/<vendor>/`. Всяка категория с ≥2 имплементации —
   `driverset` тестът го проверява.
3. **Append-only доказателства.** Събитие веднъж записано не се променя.
   `store.Verify` открива промяна, изтриване и разместване.
4. **Нищо не се вмъква като HTML в конзолата** — само текстови възли.
   UI-ът рендерира съдържание, контролирано от атакуващия.
5. **Detection изходът е сдържан.** `forge` отказва да прави правило от `ls`
   или от нормален browser user agent и публикува защо.
6. **Честност в README.** Ако нещо не е валидирано (SMB файлови операции,
   VMI), се пише изрично, не се твърди.

---

## 3. Капани, в които вече сме падали

- **`_windows.go` / `_linux.go` са implicit build constraints.** Файлът се
  компилира само на тази платформа и нищо не се чупи. Има тест-guard:
  `test/e2e/build_constraints_test.go`.
- **`pkill -f mirage-director` убива собствената shell сесия**, защото
  командният ред я съдържа. Ползвай `pgrep -x mirage-director | xargs -r kill`.
- **Toolchain:** винаги `GOTOOLCHAIN=local` (иначе тегли нов Go).
- **Port 0 в тестове** е ефемерен и не може да се реконсилира — reconcile
  тестовете подават явни портове (`freeTestPort`).
- **`bus.Close()` трябва да изчака** subscriber горутините, иначе handler-и
  пишат след „stopped cleanly".
- **`apply` трябва да реинжектира runtime опциите** (host key path, token
  lookup), иначе новите listener-и се вдигат счупени.
- **Мултиплексорът не бива да блокира read цикъла.** Доставката на данни към
  поток минава през буфериран канал; директно писане в pipe заключва целия
  тунел (head-of-line). При препълване потокът се затваря, не се блокира.
- **Затварянето на поток не бива да изхвърля недоставените данни** — отговор,
  който вече е пристигнал, се губи, защото peer-ът отговаря и затваря наведнъж.
- **`Hub.Close()` трябва да затвори и приетите сокети**, не само listener-а,
  иначе изчаква дълги read deadline-и.
- **`streamConn` трябва да спазва deadline-ите.** Всяка емулирана услуга слага
  read deadline, за да изхвърли атакуващ, който мълчи. Докато `SetDeadline`
  беше no-op, тунелирана сесия висеше, докато атакуващият държи сокета, и
  тунелът свършваше поточните id-та. `Read` селектира върху данни, таймер и
  `wake` канал, който `SetDeadline` затваря — иначе вече блокиран `Read` не
  вижда новия срок (net.Conn обещава, че го вижда).
- **`Agent.Close()` не бива да чака backoff-а.** Без `done` канал спирането на
  агент, който току-що е загубил хъба, отнемаше цял `reconnect_max`. Тестът
  `TestAgentFailsClosedWhenTheTunnelIsDown` падна от 20s на под секунда.
- **Пълна VM примамка не тръгва без проверен containment.** `farm.Provisioner`
  пита fabric драйвера преди първия старт; без fabric драйвер отказва, освен
  ако `vms.containment: unenforced` не е зададено изрично (и тогава го записва
  като събитие). Няма трети вариант — VM, който атакуващият превзема, е
  истински хост в мрежата на клиента.
- **Изгорена примамка не се рециклира и не се трие.** Нито при `revert`, нито
  при reconcile, нито когато я махнеш от манифеста. Тя е доказателството.
- **`revert` първо снима мръсното състояние.** Ако снимката се провали, revert
  се отказва — по-добре мръсна примамка, отколкото изгубено доказателство.
- **Baseline се взима след като машината е вдигната**, не от студен образ:
  иначе всеки reset струва видимо буутване.
- **Reset става само след затворен engagement**, не по таймер. Рестарт, докато
  атакуващият е вътре, е най-очевидният tell, който изобщо може да се даде.
- **Kerberos е и TCP, и UDP на порт 88.** Клиентите пробват UDP и падат към TCP,
  когато отговорът не се събира. `ListenerConfig.Protocol` избира транспорта;
  KDC-то се декларира два пъти на 88. По UDP всеки съществен отговор е
  `KRB5KRB_ERR_RESPONSE_TOO_BIG` (без e-text — иначе е amplification), което е
  и каквото истински KDC връща.
- **Планираните пароли трябва да са crackable.** AS-REP/TGS blob-овете са
  истински RC4-HMAC над истински DER, с NT hash на планирана парола с формата,
  който хората избират. Ако паролата е случайна, hashcat не я намира и
  атакуващият разбира, че акаунтът е фалшив. Стойността е в reuse-а: watcher-ът
  свързва офлайн крака с онлайн опита.
- **Един каталог, два изгледа.** LDAP и Kerberos четат от `buildHoneyDirectory`;
  ако svc_sql се вижда по LDAP, но не се roast-ва по Kerberos, атакуващият е
  намерил шева. `TestKerberosBaitAgreesWithWhatLDAPAdvertises` го пази.
- **TLS ръкостискането се прави явно в `serveAgent`.** Оставено на първия
  `Read`, проблем със сертификат излиза като „връзката не започна с hello",
  което праща човека, който вдига mTLS, точно в грешната посока.

---

## 4. Работен процес

```bash
GOTOOLCHAIN=local go build ./...
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local gofmt -l $(git ls-files '*.go')
GOTOOLCHAIN=local go test -count=1 -race ./...      # ~90s, всичко трябва да е ok
```

- Тестовете на `internal/honeyd` са бавни (~50s) заради нарочните забавяния
  при отказана автентикация — това е фийчър, не бъг.
- Commit съобщения: на български, обясняват **защо**, не какво. Всеки завършен
  етап се пушва.
- Всеки нов протокол/фийчър идва с тест, който доказва детекцията, и с тест за
  containment, ако пипа мрежата.

---

## 5. Какво следва (по приоритет)

1. **Образи за VM примамките** — платформата е готова (`internal/farm`,
   профил P4), но MIRAGE клонира готови libvirt шаблони, не ги строи.
   Липсва packer/cloud-init рецепта и `proxmox` драйвер.
2. **Life Engine** — синтетични потребители, които поддържат примамката жива
   (логове, lastLogon, нови файлове) докато атакуващият я гледа.
4. **SMB файлови операции** — за да работи ransomware двигателят и срещу
   Windows криптори. Изисква валидация срещу истински Windows клиент.
5. **VMI observer** (DRAKVUF/libvmi) — най-тежкото, изисква хипервайзор.
6. **Breadcrumbs агент** — подхвърля примамки на реални endpoint-и.
7. **`mirage-graph`** — attack path deception; изисква реална среда за профилиране.

Отхвърлени съзнателно (виж `docs/11-IDEAS.md`): hack-back, автоматично
блокиране на IP към прод firewall, cloud-only контролер.

---

## 6. Документация

`docs/00`–`docs/11` са планът: визия, архитектура, компоненти, каталог на
измамата, containment/правна рамка, модел на данните, профили на внедряване,
роудмап, стек, бизнес, интеграции, идеи. `docs/adr/` — решенията с обосновка.
