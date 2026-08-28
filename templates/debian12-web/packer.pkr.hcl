// Packer template for a Debian 12 web server decoy.
//
// This builds the golden image that profile P4 clones from. The result is a
// real Debian installation with nginx, PHP, a plausible DocumentRoot, cron jobs,
// and user accounts — indistinguishable from a production web server because it
// IS a production web server, just one that exists to be found.
//
// Usage:
//   packer build -var "proxmox_url=https://pve:8006/api2/json" \
//                -var "proxmox_token=root@pam!mirage=..." \
//                templates/debian12-web/

packer {
  required_plugins {
    proxmox = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/proxmox"
    }
  }
}

variable "proxmox_url" {
  type    = string
  default = "https://pve:8006/api2/json"
}

variable "proxmox_token" {
  type      = string
  sensitive = true
}

variable "proxmox_node" {
  type    = string
  default = "pve"
}

variable "iso_file" {
  type    = string
  default = "local:iso/debian-12-amd64-netinst.iso"
}

source "proxmox-iso" "debian12-web" {
  proxmox_url              = var.proxmox_url
  token                    = var.proxmox_token
  node                     = var.proxmox_node
  iso_file                 = var.iso_file
  insecure_skip_tls_verify = true

  vm_name  = "mirage-debian12-web"
  vm_id    = 9000
  template = true

  cores    = 2
  memory   = 2048
  os       = "l26"

  disks {
    type         = "scsi"
    disk_size    = "20G"
    storage_pool = "local-lvm"
  }

  network_adapters {
    model  = "virtio"
    bridge = "vmbr0"
  }

  ssh_username = "root"
  ssh_password = "packer"
  ssh_timeout  = "30m"

  http_directory = "."
  boot_command = [
    "<esc><wait>",
    "install auto=true priority=critical ",
    "url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "hostname=web01 domain=corp.local ",
    "<enter>"
  ]
}

build {
  sources = ["source.proxmox-iso.debian12-web"]

  provisioner "shell" {
    inline = [
      "apt-get update && apt-get upgrade -y",
      "apt-get install -y nginx php-fpm curl wget openssh-server sudo cron rsyslog",
      "systemctl enable nginx php8.2-fpm ssh cron rsyslog",

      // Create plausible users
      "useradd -m -s /bin/bash -c 'Deployment user' deploy",
      "useradd -m -s /bin/bash -c 'Backup agent' backup",
      "echo 'deploy:deploy123' | chpasswd",
      "echo 'root:P@ssw0rd' | chpasswd",

      // Plausible web content
      "echo '<html><body><h1>Internal Portal</h1></body></html>' > /var/www/html/index.html",
      "mkdir -p /var/www/html/admin /var/www/html/api",

      // Cloud-init for dynamic identity
      "apt-get install -y cloud-init",
      "systemctl enable cloud-init",

      // Clean up for templating
      "apt-get clean",
      "truncate -s 0 /etc/machine-id",
      "rm -f /etc/ssh/ssh_host_*",
      "rm -f /var/log/*.log /var/log/auth.log",
    ]
  }
}
