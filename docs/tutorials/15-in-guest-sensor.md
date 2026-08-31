# 15 — In-guest сензор (пълен мониторинг на всеки хипервайзор)

DRAKVUF вижда всяка команда, но иска Xen + VMFUNC CPU. Този туториал е за
**виждане на всяка команда вътре в пълна VM примамка на всеки хипервайзор** —
KVM/Proxmox/VMware/Hyper-V — чрез лек in-guest сензор.

Всяка команда (`ls`, `id`, `sudo su`, `powershell iwr http://...`) стига до
доказателствената верига и се връзва в engagement-а точно като DRAKVUF sighting.

## Как работи

```
[guest: mirage-sensor] --(sightings, token)--> [director: agent observer] --> ingest → верига + engagement + аларми
```

- **Linux**: сензорът чете kernel process-events connector (netlink) — хваща
  всеки fork/exec system-wide, self-contained (без auditd). Иска root.
- **Windows**: чете Sysmon Event ID 1 (process create). Sysmon е стандартна
  корпоративна телеметрия — декой с него изглежда **по-реалистичен**, не
  по-малко.

Честно: това е **agent-based**, не agentless — има сензор в госта. Observer-ът
не декларира `CapAgentless` и конзолата го показва. За crown-jewel декой на Xen
ползвай DRAKVUF (нулев tell); навсякъде другаде — този сензор.

## 1. Вдигни приемника (director)

```yaml
drivers:
  compute: proxmox        # или vsphere/hyperv/libvirt
  observer: agent
  observer_config:
    listen: 0.0.0.0:8423  # където сензорите се свързват
    token: "СПОДЕЛЕН-ТАЙНИ-ТОКЕН"
    # tls_cert / tls_key — препоръчано извън localhost
```

Off-localhost сложи TLS (или пусни връзката през presence overlay тунела) —
телеметрията от госта не бива да пътува в чист текст.

## 2. Пусни сензора в примамката

Копирай `mirage-sensor` в декоя (кръсти го така, че да се слее — напр.
`systemd-telemetryd`) и го пусни като услуга.

**Linux** (като root):
```bash
./mirage-sensor \
  --director https://mirage:8423 \
  --token "СПОДЕЛЕН-ТАЙНИ-ТОКЕН" \
  --decoy-id dcy-web01
```

**Windows** (Sysmon трябва да е инсталиран и да логва):
```powershell
mirage-sensor.exe --director https://mirage:8423 --token "..." --decoy-id dcy-web01
```

`--decoy-id` трябва да съвпада с id-то, с което MIRAGE знае декоя (за да се
връзва в правилния engagement).

## 3. Виж командите

Влизат през секция **Observer / VMI** и в engagement-а като process събития с
`command_line`, `user`, `pid`. `sudo su`, `iwr`/`wget` payload URL-ите се
класифицират и вдигат аларми точно като на емулираната SSH повърхност.

## Инженерни гаранции

- Сензорът **никога не блокира** процеса, който наблюдава: батч опашка с
  drop-oldest при препълване.
- При кратък отпад на director-а батчът се **re-queue-ва** — нищо не се губи.
- Приемникът fan-out-ва per-decoy през буфериран канал, drop-on-overflow —
  флудещ сензор не спира director-а (урокът от presence мултиплексора).
- Токенът е **задължителен**; отворен ingest на security продукт е liability.

## Кога кое

| Ситуация | Наблюдение |
|---|---|
| Емулиран SSH/telnet декой | Вече пълен keystroke запис, навсякъде (нищо не се прави) |
| Full-OS декой на Xen + VMFUNC | DRAKVUF (agentless, нулев tell) |
| Full-OS декой на KVM/VMware/Hyper-V | **този in-guest сензор** |
| Файлов дял | Ransomware trap ([12](12-ransomware-trap.md)) |

Комбинирани — виждаш всяка команда, всеки клавиш, всяко качване, навсякъде.
