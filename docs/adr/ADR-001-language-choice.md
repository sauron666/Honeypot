# ADR-001 — Езици: Go за платформата, Rust за hot path

**Статус:** приет · **Дата:** 2026-08-28

## Контекст
Продуктът е on-prem appliance, който трябва да се инсталира лесно, да обработва
голям поток събития и да има нискониво достъп до KVM/libvmi.

## Решение
- **Go** за всички control/data plane услуги (director, provisioner, honeyd, gateway,
  tokens, brain, forge, breadcrumbs агент, CLI).
- **Rust** (с C FFI) само за `observer` (libvmi/DRAKVUF бридж) и за capture hot path,
  ако Go се окаже недостатъчен.
- **Python** само за sandbox-нати аналитични plugin-и (Volatility3, YARA, парсери).
- **TypeScript/React** за UI.

## Причини
Go дава един статичен бинар без runtime зависимости — критично за appliance и за
breadcrumb агента. GC паузите са приемливи навсякъде освен при непрекъснат syscall
поток и line-rate capture, където Rust е правилният избор. Python е незаменим за
форензичните библиотеки, но не бива да е в решаващия път.

## Последствия
+ Прост deploy, малка повърхност, добра производителност.
− Два системни езика = по-висока бариера за контрибутори; изолираме Rust в един модул.
