# 12 — Ransomware trap (навсякъде, не само на Xen)

DRAKVUF наблюдава отвътре, но иска Xen + VMFUNC CPU. Този туториал е за
**защитата от ransomware, която работи на всеки хипервайзор** — KVM/Proxmox,
VMware, Hyper-V — без VMI и без агент в госта.

Идеята: MIRAGE сервира примамлив мрежов дял (Finance/HR/Backups) от userspace
файлова система (FUSE). Всяка операция минава през ransomware детектора и
**tarpit-а** ПРЕДИ да докосне диска. Криптор, който удари дяла, се засича за
2-3 операции и се задавя, а нормалното разглеждане е моментално.

## Как работи (накратко)

1. Всеки write храни детектора: ентропия, разрушен file-type, масова смяна на
   разширение, скорост, canary, бележка за откуп.
2. **Tarpit**: забавянето расте квадратично със съмнението. Нула при нормален
   потребител; секунди, щом крипторът е потвърден — това го души.
3. При потвърждение: snapshot на декоя (пази местопрестъплението на реалния
   хипервайзор) + critical T1486 събитие в доказателствената верига.

Портируемият мозък е тестван на всяка платформа; FUSE монтажът е само за Linux
хост (иска `/dev/fuse`).

## Конфигурация

```yaml
trap:
  enabled: true
  mountpoint: /srv/mirage/fileserver     # където се монтира bait дялът
  share_id: fileserver-finance           # името в събитията
  snapshot_decoy: dcy-fileserver         # (по избор) кой VM декой да снима при потвърждение
```

Стартирай директора нормално. В лога ще видиш:

```
ransomware trap armed   share=fileserver-finance mountpoint=/srv/mirage/fileserver
ransomware trap mounted mountpoint=/srv/mirage/fileserver
```

Ако mount-ът се провали (не Linux, няма `/dev/fuse`, зает mountpoint) —
директорът **не спира**; логва warning и продължава (детекторът пак работи през
емулираните FTP/SMB услуги). Това е защита-в-дълбочина, не single point of
failure.

## Как да го изложиш на атакуващия

`mountpoint` е локална директория. Изложи я като мрежов дял, за да я намери
ransomware:

- Пусни Samba/NFS export върху `mountpoint` → изглежда като `\\fileserver\finance`.
- Или монтирай го от пълна VM примамка (виж [05](05-full-vm-decoys.md)).
- Или го подхвърли като следа с [breadcrumbs](09-breadcrumbs.md) (.rdp/креденшъли
  към „fileserver").

## Наблюдение от конзолата (GUI)

Секция **Ransomware Trap**:

- Статус: quiet / suspicious / **RANSOMWARE CONFIRMED**.
- Suspicion метър (score).
- Impact метрики: файлове докоснати, операции до пръв сигнал/потвърждение,
  наложено tarpit време, нови разширения, текст на бележката.
- Съдържанието на bait дяла с маркирани **canary** файлове.

От API: `GET /api/trap` връща същото (verdict + metrics + listing).

## Тест на живо

```bash
# монтирай, изложи по SMB, после от декоя пусни безобиден криптор върху дяла:
for f in /mnt/fileserver/Finance/*; do
  openssl enc -aes-256-cbc -pass pass:x -in "$f" -out "$f.locked" && rm "$f"
done
```

Гледай конзолата: score скача, статусът става CONFIRMED, snapshot-ът гърми,
а всяка следваща операция се бави все повече.

## Изследване

Пълната методология и измерванията (detection latency, files spared) са в
`docs/research/ransomware-tarpit.md`. Числата се регенерират от тестовете:

```bash
GOTOOLCHAIN=local go test -v -run 'Metrics|Tarpit|Confirmed|Browsing' ./internal/fusetrap/
```

## Граници (честно)

- Внимателен атакуващ може да разпознае FUSE mount или самото забавяне и да го
  избегне. Стойността е най-висока срещу автоматични, безразборни криптори —
  честият случай.
- Криптор, който пише само НОВИ файлове и трие оригиналите, пропуска magic-loss
  сигнала; пак се лови (ентропия + скорост + canary), но потвърждението може да
  дойде няколко операции по-късно.
