#!/usr/bin/env bash
# Generate a libvmi ISF profile for a running Windows guest, so DRAKVUF can give
# full introspection (procmon/regmon/filetracer/injection) rather than only a
# process listing.
#
# This encodes the exact, live-validated workflow from ADR-010: it was confirmed
# against Windows Server 2025 (build 26100) on Xen 4.20. Run it in dom0 with the
# Windows guest running.
#
#   ./generate-isf-profile.sh <xen-domain-name>
#
# It writes:
#   /etc/libvmi.conf entry for the domain (with volatility_ist pointing at the ISF)
#   <domain>.json  — the ISF (Intermediate Symbol File) volatility3/libvmi read
#
# Prerequisites in dom0: xen-utils, libvmi (with the volatility_ist patch),
# python3 + volatility3 (for pdbconv), and network access to Microsoft's symbol
# server (or a local PDB).
set -euo pipefail

DOMAIN="${1:?usage: generate-isf-profile.sh <xen-domain-name>}"
OUT="${2:-${DOMAIN}.json}"
LIBVMI_CONF="${LIBVMI_CONF:-/etc/libvmi.conf}"

command -v vmi-win-guid >/dev/null || { echo "vmi-win-guid not found (install libvmi tools)"; exit 1; }
command -v vol >/dev/null || command -v volatility3 >/dev/null || {
  echo "volatility3 not found (pip install volatility3)"; exit 1; }
VOL="$(command -v vol || command -v volatility3)"

echo ">> reading the guest kernel GUID from domain '$DOMAIN'"
# vmi-win-guid prints the PDB filename and its GUID+age, which together identify
# the exact kernel build so the right symbols are fetched.
GUID_OUT="$(vmi-win-guid name "$DOMAIN")"
echo "$GUID_OUT"

PDB="$(echo "$GUID_OUT" | grep -oiE 'PDB GUID: [0-9a-f]+' | awk '{print $3}')"
KERNEL="$(echo "$GUID_OUT" | grep -oiE 'Kernel filename: [^ ]+' | awk '{print $3}')"
PDB="${PDB:?could not read PDB GUID — is the guest running and a supported Windows?}"
KERNEL="${KERNEL:-ntkrnlmp.pdb}"

echo ">> fetching symbols and building the ISF for ${KERNEL} (${PDB})"
# volatility3's pdbconv fetches the matching PDB from Microsoft's symbol server
# and converts it to an ISF JSON that both volatility3 and libvmi consume.
python3 -m volatility3.framework.symbols.windows.pdbconv \
  -p "$KERNEL" -g "$PDB" -o "$OUT"

echo ">> ISF written to $OUT"

# Wire it into libvmi. The KEY IS volatility_ist -- NOT json_path (a live trap
# from ADR-010: the flex/bison parser silently rejects json_path).
echo ">> updating $LIBVMI_CONF"
if grep -q "^${DOMAIN} " "$LIBVMI_CONF" 2>/dev/null; then
  echo "   an entry for $DOMAIN already exists; edit it by hand to avoid clobbering"
else
  cat >> "$LIBVMI_CONF" <<CONF
${DOMAIN} {
    ostype = "Windows";
    volatility_ist = "$(readlink -f "$OUT")";
}
CONF
  echo "   added a libvmi entry for $DOMAIN"
fi

echo
echo "Done. Verify with:  vmi-process-list ${DOMAIN}"
echo "Then MIRAGE's observer (drivers.observer: drakvuf) will get full events."
