# 14 — Хипервайзори (KVM/Proxmox/VMware/Hyper-V)

Клиентите карат различни хипервайзори. MIRAGE има compute драйвер за всеки от
основните, за да разгъваш пълни VM примамки навсякъде.

> **Най-важното първо:** защитата от ransomware и мониторингът **не зависят** от
> compute драйвера. Ransomware trap-ът ([12](12-ransomware-trap.md)) е мрежов
> дял, а доказателствата и детекцията са platform-agnostic. Дори без compute
> драйвер за твоята платформа, декоят просто монтира дяла и си защитен.

## Кой драйвер за какво

| Драйвер | Платформа | Статус | Auth |
|---|---|---|---|
| `inproc` | in-process (тест/демо) | стабилен | — |
| `podman` | контейнери | стабилен | локален |
| `libvirt` | **KVM/QEMU** директно | стабилен | libvirt socket |
| `proxmox` | Proxmox VE | **валидиран на PVE 8.4** | ticket / API token, TLS fingerprint |
| `vsphere` | VMware vCenter 7/8 | **experimental** | session, TLS fingerprint |
| `hyperv` | Microsoft Hyper-V | **experimental** | PowerShell локално / SSH |

„Experimental" значи честно: кодът е unit-тестван срещу синтетични отговори, но
**още не е валидиран на жив хипервайзор**. Драйверът го обявява (`Info().
Experimental`), а конзолата го показва. proxmox е field-proven; vsphere/hyperv
чакат жива валидация.

## KVM (libvirt)

```yaml
drivers:
  compute: libvirt
  compute_config:
    uri: qemu:///system
```

## Proxmox

```yaml
drivers:
  compute: proxmox
  compute_config:
    url: https://pve.example:8006
    node: pve
    token_id: "root@pam!mirage"
    token_secret: "…"
    tls_fingerprint: "AB:CD:…"   # пинва self-signed сертификата
```

## VMware vSphere (experimental)

```yaml
drivers:
  compute: vsphere
  compute_config:
    url: https://vcenter.example
    user: "administrator@vsphere.local"
    password: "…"
    tls_fingerprint: "AB:CD:…"
```

Session auth към vSphere Automation REST API. `Create` е **adopt-first**:
осиновява съществуваща VM по име, иначе клонира от `template`. Поддържа
power/status/list, snapshot, revert.

## Hyper-V (experimental)

```yaml
drivers:
  compute: hyperv
  compute_config:
    host: "admin@hv01"     # през SSH; махни за локален Windows хост
    powershell: pwsh
```

Кара PowerShell cmdlets (Get-VM/Start-VM/Checkpoint-VM…) локално или през SSH.
`Create` от template е VHDX differencing disk (златният образ не се пипа).

## Containment важи за всички

Независимо от драйвера, **containment преди старт** е задължителен
([05](05-full-vm-decoys.md)): `farm.Provisioner` пита fabric драйвера, преди
първия старт. VM, който атакуващият превзема, е истински хост в мрежата.

## Как да помогнеш за валидация

Ако имаш жив vCenter или Hyper-V хост: пусни `miragectl doctor` с драйвера, после
пробвай list/start/stop/snapshot и докладвай. Драйверите ще минат от experimental
към field-proven, когато има жива валидация — точно както proxmox и DRAKVUF.
