# Golden Templates

MIRAGE клонира готови шаблони, не ги строи от нулата при всяко deploy. Тази
директория съдържа Packer/cloud-init рецептите за тях.

## Налични шаблони

| Директория | Персона | Какво е |
|---|---|---|
| `ubuntu2404-cloud/` | linux/* | Ubuntu 24.04 cloud-init; универсален шаблон за клониране |
| `debian12-web/` | linux/web | Debian 12 + nginx + PHP; уеб портал (Packer) |
| `debian12-fileserver/` | linux/fileserver | Debian 12 + Samba; файлов сървър с canary share |
| `win2022-dc/` | windows/dc | Windows Server 2022 + AD DS; домейн контролер (бъдещо) |

## Как се строи

### Ubuntu 24.04 cloud-init (препоръчван)

Най-бързият начин — не изисква Packer, сваля cloud image и го
конвертира в шаблон директно на Proxmox нода:

```bash
ssh root@proxmox bash < templates/ubuntu2404-cloud/build-template.sh
```

Или с environment variables:

```bash
VMID=9000 STORAGE=local-lvm BRIDGE=vmbr1 \
  ssh root@proxmox bash < templates/ubuntu2404-cloud/build-template.sh
```

### Debian 12 (Packer)

```bash
packer build -var "proxmox_url=https://pve:8006/api2/json" \
             -var "proxmox_token=root@pam!mirage=YOUR-TOKEN" \
             -var "proxmox_node=pve" \
             templates/debian12-web/

# libvirt/KVM
packer build -var "output_dir=/var/lib/libvirt/images" \
             templates/debian12-web/
```

## Cloud-init

Всеки шаблон има `cloud-init.yaml`, който дава на всеки клон уникална
идентичност (hostname, SSH ключове, machine-id, потребители). Директорът го
подава чрез compute драйвера при клониране.

## Принципи

- Шаблонът е **истинска инсталация**, не stub — иначе атакуващият я разпознава.
- SSH host ключовете се генерират при клониране, не при build — два клона с
  един и същ ключ са два клона, които се издават взаимно.
- `/etc/machine-id` се трънква при build, за да се генерира при boot.
- Паролите идват от cloud-init, не от шаблона — иначе всеки клон споделя
  паролата на шаблона.
