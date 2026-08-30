#!/bin/bash
# build-template.sh — Create a cloud-init Ubuntu 24.04 template on Proxmox VE
#
# This script creates a VM template that MIRAGE clones for full-OS decoys.
# It downloads the Ubuntu cloud image (if not cached), imports it as a disk,
# attaches cloud-init, and converts the VM to a template.
#
# Usage:
#   PVE_URL=https://192.168.1.100:8006 \
#   PVE_USER=root@pam \
#   PVE_PASSWORD='Nqm@parol@' \
#   PVE_NODE=proxmox \
#   bash templates/ubuntu2404-cloud/build-template.sh
#
# Or run on the Proxmox node itself (no PVE_URL needed):
#   ssh root@proxmox bash < templates/ubuntu2404-cloud/build-template.sh

set -euo pipefail

VMID="${VMID:-9000}"
VMNAME="${VMNAME:-mirage-ubuntu2404}"
STORAGE="${STORAGE:-local-lvm}"
BRIDGE="${BRIDGE:-vmbr1}"
MEMORY="${MEMORY:-2048}"
CORES="${CORES:-2}"

CLOUD_IMG_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
CLOUD_IMG="noble-server-cloudimg-amd64.img"

echo "=== MIRAGE template builder ==="
echo "VMID:    $VMID"
echo "Name:    $VMNAME"
echo "Storage: $STORAGE"
echo "Bridge:  $BRIDGE"

# --- Download cloud image ---
if [ ! -f "/tmp/$CLOUD_IMG" ]; then
    echo "Downloading Ubuntu 24.04 cloud image..."
    wget -q --show-progress -O "/tmp/$CLOUD_IMG" "$CLOUD_IMG_URL"
else
    echo "Using cached image: /tmp/$CLOUD_IMG"
fi

# --- Check if template already exists ---
if qm status "$VMID" &>/dev/null; then
    echo "ERROR: VMID $VMID already exists. Remove it first or choose a different VMID."
    echo "  qm destroy $VMID --purge"
    exit 1
fi

# --- Create VM ---
echo "Creating VM $VMID ($VMNAME)..."
qm create "$VMID" \
    --name "$VMNAME" \
    --memory "$MEMORY" \
    --cores "$CORES" \
    --cpu cputype=host \
    --net0 "virtio,bridge=$BRIDGE" \
    --scsihw virtio-scsi-pci \
    --ostype l26 \
    --agent enabled=1 \
    --serial0 socket \
    --vga serial0 \
    --boot order=scsi0

# --- Import cloud image as disk ---
echo "Importing cloud image as disk..."
qm set "$VMID" --scsi0 "$STORAGE:0,import-from=/tmp/$CLOUD_IMG"

# --- Resize disk ---
echo "Resizing disk to 20G..."
qm disk resize "$VMID" scsi0 20G

# --- Add cloud-init drive ---
echo "Adding cloud-init drive..."
qm set "$VMID" --ide2 "$STORAGE:cloudinit"

# --- Configure cloud-init defaults ---
echo "Setting cloud-init defaults..."
qm set "$VMID" \
    --ciuser deploy \
    --cipassword "deploy123" \
    --ipconfig0 "ip=dhcp" \
    --sshkeys "" \
    --citype nocloud

# --- Convert to template ---
echo "Converting to template..."
qm template "$VMID"

echo ""
echo "=== Template $VMID ($VMNAME) ready ==="
echo ""
echo "MIRAGE can now clone it. Add to your profile:"
echo ""
echo "  drivers:"
echo "    compute: proxmox"
echo "    compute_config:"
echo "      url: \"https://$(hostname -I | awk '{print $1}'):8006\""
echo "      user: \"root@pam\""
echo "      password: \"...\""
echo "      node: \"$(hostname)\""
echo ""
echo "  vms:"
echo "    decoys:"
echo "      - id: vm-web01"
echo "        template: \"$VMID\""
echo "        persona: linux/web"
echo "        cpus: 2"
echo "        memory_mb: 1024"
