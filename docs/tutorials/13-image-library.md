# 13 — Библиотека с образи (ISO/OVA/OVF/qcow2)

Декой без правдоподобна машина е слаб декой. Библиотеката ти дава да **сменяш
лесно образите**: внеси свой hardened Ubuntu, CTF машина (HackTheBox, VulnHub),
Windows build — тагни ги по трудност (easy/medium/hard/insane) и ги сменяй.

Преди образ, който **не си правил ти**, да стане жив декой, той трябва да е
**саниран**: махнати CTF флагове, ресетнати познати креденшъли, вграден
watermark. Иначе атакуващият вижда `user.txt`/`root.txt` и разбира, че е CTF.

> HTB/VulnHub образите са **тяхна собственост**. Внасяш **своя** копие; MIRAGE
> не ги дистрибутира.

## Внеси образ

```bash
# референцира по път — не копира; голям образ струва само checksum
./bin/miragectl images import \
  --file /srv/images/box.qcow2 \
  --difficulty insane --persona linux/web --source htb
```

Форматът се разпознава от разширението (iso/ova/ovf/qcow2/vmdk/vhdx/raw).

## Виж и тагни

```bash
./bin/miragectl images list
./bin/miragectl images list --difficulty hard --sanitized

# смени трудност / тагове
./bin/miragectl images retag --id box --difficulty hard --tags "web,rce"
```

От конзолата: секция **Image Library** — inline селектор за трудност, статус
„sanitised/NOT sanitised", преглед на плана, remove.

## Санирай (махни флаговете)

Първо **dry-run** (нищо не се пипа):

```bash
./bin/miragectl images sanitize --id box
```

Показва плана: кои флаг файлове ще се махнат (`/root/root.txt`, `/home/*/user.txt`,
`C:/Users/*/Desktop/*.txt`…), кои акаунти се ресетват (root/administrator),
watermark-ът, hygiene командите (bash история, authorized_keys).

После **приложи** (иска libguestfs `virt-customize`):

```bash
./bin/miragectl images sanitize --id box --apply
```

Ако `virt-customize` липсва, MIRAGE **не лъже**, че е санирал — печата командата,
която би изпълнил, за да я пуснеш ръчно, и не маркира образа като deployable.
Инсталирай: `apt install libguestfs-tools`.

Ресетнатите пароли се печатат веднъж — запиши ги.

## Махни от каталога

```bash
./bin/miragectl images remove --id box
```

Забравя записа; **файлът на диска остава** (твой е).

## Как да качиш образа на хипервайзора (ISO/OVA/VMDK)

Каталогът **референцира по път** — образът трябва първо да е на хипервайзора,
после `images import` го регистрира. Качването зависи от платформата:

### Proxmox (KVM/QEMU)
```bash
# ISO → в ISO storage-а (за инсталация from scratch)
scp box.iso root@pve:/var/lib/vz/template/iso/

# qcow2/raw диск → внеси го в нова VM
qm create 9001 --name box-template --memory 2048 --net0 virtio,bridge=vmbr0
qm importdisk 9001 box.qcow2 local-lvm          # внася диска
qm set 9001 --scsi0 local-lvm:vm-9001-disk-0
qm template 9001                                 # прави го template за linked clone

# OVA/OVF → разархивирай и внеси vmdk-то
tar -xf box.ova && qm importovf 9001 box.ovf local-lvm
```
После: `miragectl images import --file /var/lib/vz/images/9001/... --format qcow2`
и в манифеста `template: box-template` (proxmox драйверът клонира по име).

### VMware vSphere
```bash
# OVA/OVF native — deploy през govc (или Web Client)
govc import.ova -name=box-template box.ova
# VMDK → качи в datastore
govc datastore.upload box.vmdk box-template/box.vmdk
```
`template` в манифеста = името на VM-а/template-а; vsphere драйверът е adopt-first.

### Hyper-V
```powershell
# VHDX → копирай на хоста, използвай като parent за differencing disk
Copy-Item box.vhdx C:\Templates\box.vhdx
# hyperv драйверът прави differencing disk от него при Create
```
`template` = пътят до parent VHDX-а.

### libvirt/KVM директно
```bash
cp box.qcow2 /var/lib/libvirt/images/box-template.qcow2
virsh define box-template.xml     # дефинирай template домейна
```

> **Формати:** KVM/Proxmox → qcow2/raw; VMware → OVA/OVF/VMDK; Hyper-V → VHDX.
> Каталогът разпознава формата от разширението и го пази, за да знае драйверът
> дали може да го консумира директно.

## Разгъни като декой

Санираният образ се подава на пълна VM примамка през `template` в манифеста
(виж [05](05-full-vm-decoys.md)). Каталогът пази пътя и формата, за да знае
compute драйверът дали може да го консумира директно.

## Работен процес

1. `images import` — регистрирай образа, тагни трудността.
2. `images sanitize --id … ` (dry-run) — виж какво ще се махне.
3. `images sanitize --id … --apply` — санирай, маркирай deployable.
4. Подай го като `template` на VM декой; containment преди старт ([05](05-full-vm-decoys.md)).
