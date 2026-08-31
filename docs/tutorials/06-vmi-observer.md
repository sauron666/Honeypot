# 06 — VMI наблюдение (agentless)

Агент в госта е tell — атакуващият го намира. **Virtual Machine Introspection**
(VMI) гледа VM-а отвън, от хипервайзора, без нищо в самата примамка. MIRAGE
интегрира **DRAKVUF** върху **Xen**.

Това е най-мощната, но и най-взискателната към хардуера способност. Тук е
честният ѝ статус.

## Изисквания към хардуера

DRAKVUF иска **CPU с VMFUNC (altp2m)**, не само VT-x/EPT:

- i3-9100T (Coffee Lake) — има EPT, **няма VMFUNC** → DRAKVUF не тръгва.
- i5-1035G1 (Ice Lake) — **има VMFUNC** → работи.

`libvmi` и `vmi-dump-memory` работят и без VMFUNC (памет dump, process list).
Пълните shadow-page hooks (exec, file, registry) искат altp2m.

## Настройка (накратко)

Капаните, платени на живо:

- Xen 4.20: boot параметър `altp2m=1` (не `=mixed`, който е невалиден).
- Domain config: `altp2m = "external"` (не `"mixed"`).
- libvmi config ключът е `volatility_ist` (не `json_path` — flex/bison
  парсерът не го разпознава и дава неясна грешка).
- ISF профил: `dwarf2json` (Linux) или `volatility3 pdbconv` (Windows).

За Windows guest има turnkey скрипт:
`templates/windows-vmi/generate-isf-profile.sh` + README.

## Какво виждаш — Linux vs Windows

Живо откритие (валидирано на реален DRAKVUF):

- **Linux guest**: DRAKVUF дава само process listing (`RunningProcess` формат,
  без UserId/TID/CommandLine). `syscalls`/`filetracer` плъгините не закачат
  нищо. Парсерът маркира listing като informational — **не** като „процес
  стартиран" (иначе всяко обхождане би вдигало фалшива HIGH аларма).
- **Windows guest**: пълна интроспекция. Валидирано на Windows Server 2025
  (build 26100): 11 533 regmon + 190 filetracer + 230 procmon за 80s. Тук
  triggered events (exec, file delete, registry) идват с ProcessName/UserId/TID.

За пълна VMI интроспекция → **Windows guest + Windows ISF профил**.

## Управление от конзолата (GUI)

Секция **Observer / VMI**:

- Статус на драйвера (`none` или `drakvuf`) и Probe резултат (проверява
  `/proc/xen/capabilities`, dom0, `xl` на PATH).
- **Dump** — сваля паметта на избрана VM примамка (`vmi-dump-memory` или
  `xl dump-core`) за форензика.

Observer-ът се закача **след** Reconcile (VM-ът трябва да е running, преди
DRAKVUF да тръгне срещу него). Спирането е обратно: първо observer-ите, после
фермата.

## Crypto hook — ransomware отвътре

`apimon` закача `BCryptEncrypt`. Криптиране вътре в примамка без легитимен
потребител е ransomware, докато не се докаже друго → **critical**, T1486.

## Ако нямаш VMFUNC хардуер

VM примамките работят на Proxmox (KVM/QEMU) и без Xen — просто без agentless
VMI. Хващаш всичко по мрежата и в емулираните услуги; губиш само наблюдението
отвътре в госта. Това е съзнателен компромис, не бъг.

## Какво следва

- [Доказателства и Vault](10-evidence-vault.md) — memory dump-ът също е
  доказателство; подпечатай веригата.
