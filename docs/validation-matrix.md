# Матрица за валидация на хипервайзорите

Драйверите `vsphere` и `hyperv` са **experimental**, докато не минат жива
валидация — точно както `proxmox` е field-proven на PVE 8.4, а DRAKVUF на Xen
4.20. Този документ е runbook-ът: какво да пуснеш на всеки жив хост, за да
свалиш флага.

## Кои хипервайзори и колко теста

| Хипервайзор | Драйвер | Статус сега | Guest-и за тест |
|---|---|---|---|
| Proxmox VE | `proxmox` | ✓ field-proven (PVE 8.4) | Linux + Windows |
| VMware vCenter 7/8 | `vsphere` | experimental | Linux + Windows |
| Microsoft Hyper-V | `hyperv` | experimental | Linux + Windows |

За всеки хипервайзор: **2 теста** — един Linux guest, един Windows guest.
Общо 3 хипервайзора × 2 = 6 прогона.

## Smoke-test (автоматизиран lifecycle)

`miragectl vms smoketest` кара драйвера директно (не през running director) през
целия жизнен цикъл: probe → create (adopt/clone) → start → status(running) →
snapshot → revert → stop. Snapshot/revert се пропускат, ако драйверът не ги
декларира.

```bash
# 1. Конфигурирай драйвера в профил (виж туториал 14)
#    напр. profiles/vsphere.yaml с drivers.compute: vsphere

# 2. Пусни срещу Linux template
./bin/miragectl vms smoketest \
  --config profiles/vsphere.yaml \
  --template ubuntu-2404-template \
  --name mirage-val-linux --cleanup

# 3. Пусни срещу Windows template
./bin/miragectl vms smoketest \
  --config profiles/vsphere.yaml \
  --template win2022-template \
  --name mirage-val-win --settle 60 --cleanup
```

Windows буутва по-бавно → `--settle 60`. Без `--cleanup` VM-ът остава за оглед.

## Критерии за приемане (на прогон)

- **probe** PASS — драйверът достига хоста и се автентикира.
- **create** PASS — осиновява съществуваща VM по име, или клонира от template.
- **start** PASS + **status is running** PASS — VM-ът тръгва и се вижда running.
- **snapshot** + **revert** PASS (където драйверът ги поддържа).
- **stop** PASS.
- Ръчно: провери, че декоят е достижим по мрежата в containment зоната.

Ако и Linux, и Windows прогонът минат чисти → драйверът е валидиран.
Докладвай (issue/PR), за да падне `Experimental` флагът: махни `Experimental:
true` от `…Info()` и обнови теста `Test…IsExperimental` + CLAUDE.md.

## Отделно: пълен in-guest мониторинг

Smoke-тестът валидира **управлението** (compute драйвера). Наблюдението отвътре
в guest-а е отделна ос:

- **Емулирани услуги (honeyd)** — пълен запис на всяка команда/клавиш/качване,
  на **всеки** хипервайзор (не зависи от compute драйвера).
- **Ransomware trap** — всяка файлова операция на дяла, на всеки хипервайзор.
- **DRAKVUF VMI** — process exec с команден ред, само на Xen + VMFUNC CPU
  (валидиран на Windows Server 2025).
- **Full-OS decoy на KVM/VMware/Hyper-V без VMI** — вътрешните команди в
  локалния shell на guest-а НЕ се виждат агентлес; вижда се мрежа + trap +
  емулирани услуги. За пълен keystroke вътре трябва in-guest сензор (виж
  бележката в края на туториал 14 и обсъждането за слоесто наблюдение).
