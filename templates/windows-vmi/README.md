# Windows VMI — пълна интроспекция на пълна VM примамка

Целта: DRAKVUF да дава **пълни** събития (процеси, регистър, файлове, инжекции)
за Windows guest, а не само process listing (какъвто дава Linux guest). Живо
валидирано на **Windows Server 2025 (build 26100), Xen 4.20, i5-1035G1** — виж
`docs/adr/ADR-010-vmi-observer.md`.

## Защо Windows

DRAKVUF triggered plugin-ите (procmon exec, regmon, filetracer, injection)
закачат Windows kernel hooks. На Linux guest те не закачат нищо — получаваш само
`RunningProcess` listing. За дълбоко наблюдение примамката трябва да е Windows.

Живо измерено за 80 секунди нормална работа:

| Plugin | Събития | Какво дава |
|--------|--------:|------------|
| regmon | 11 533 | всяка промяна в регистъра (persistence, config) |
| filetracer | 190 | създаване/изтриване/запис на файлове |
| procmon (triggered) | 230 | реални exec-и с CommandLine/UserId |
| syscall/sysret | ~хиляди/сек | **нарочно пропуснати** — прекалено шумни за веригата |

## Хардуер и Xen

- **CPU с VMFUNC/altp2m** — Ice Lake или по-нов. Coffee Lake (i3-9100T) няма и
  DRAKVUF не тръгва. Провери с `xl dmesg | grep -i altp2m`.
- Xen 4.20: boot параметър `altp2m=1` (**не** `=mixed`); в domain config
  `altp2m = "external"` (**не** `"mixed"` — гърми с HVM_PARAM_ALTP2M грешка).
- При crash/timeout vm_event остава заключен → `xl destroy <dom>` + `xl create`.

## Стъпки

1. Вдигни Windows guest като HVM domain на Xen с `altp2m = "external"`.
2. Генерирай ISF профила (в dom0, докато guest-ът върви):

   ```bash
   ./generate-isf-profile.sh <xen-domain-name>
   ```

   Скриптът чете kernel GUID-а (`vmi-win-guid`), тегли съответния PDB и го
   конвертира до ISF с volatility3 pdbconv, после добавя запис в `/etc/libvmi.conf`
   с ключа **`volatility_ist`** (не `json_path` — flex/bison парсерът тихо
   отхвърля `json_path`).

3. Провери libvmi:

   ```bash
   vmi-process-list <xen-domain-name>
   ```

4. Насочи MIRAGE към Xen и пусни observer-а — профил `profiles/p5-xen-vmi.yaml`:

   ```yaml
   drivers:
     compute: libvirt
     compute_config: { uri: "xen:///system" }
     observer: drakvuf
     observer_config: { drakvuf: /usr/local/bin/drakvuf }
   ```

   `miragectl doctor` проверява Xen/altp2m/dom0 преди старт. При стартиране на
   VM примамка MIRAGE закача observer-а автоматично; всяко събитие минава през
   `SightingToEvent` в доказателствената верига с правилен severity и ATT&CK.

## Какво прави MIRAGE с тези събития

- **regmon** запис в Run/RunOnce → HIGH, T1547.001 (persistence).
- **filedelete** → HIGH, T1485 (ransomware/wiper — ransomware детекторът го
  подхваща).
- **procmon exec** на discovery команда (whoami/net/nltest) → HIGH, T1059+T1057.
- **injection** (CreateRemoteThread и др.) → CRITICAL, T1055.
- **procmon listing** (RunningProcess) → informational инвентар, не аларма.
