#!/usr/bin/env bash
# R104: real Microsoft Evaluation ISO clean installation into a disposable
# NO-NIC Windows guest. NO driver/WFP/production service or paid resource.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${GITHUB_REPOSITORY:-}" != Morandi-official/Oracle-Proxy-Infrastructure ||
      "${GITHUB_EVENT_NAME:-}" != pull_request ]]; then
  echo R104_REFUSED_NOT_STANDARD_PUBLIC_HOSTED_PR; exit 4
fi
python3 - "$GITHUB_EVENT_PATH" <<'PY'
import json,sys
e=json.load(open(sys.argv[1]))
assert e["repository"]["visibility"]=="public"
assert e["repository"]["private"] is False
assert e["repository"]["full_name"]=="Morandi-official/Oracle-Proxy-Infrastructure"
assert e["pull_request"]["head"]["repo"]["full_name"]==e["repository"]["full_name"]
assert e["pull_request"]["head"]["ref"]=="test/r104-official-iso-first-windows-install-20261018"
PY
work=$(mktemp -d "${RUNNER_TEMP:?}/r104-isolated-install.XXXXXXXX")
[[ "$work" == "$RUNNER_TEMP"/r104-isolated-install.* ]] || exit 4
pid=''
kvm_acl=false
iso_mounted=false
cleanup() {
  set +e
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; fi
  if $iso_mounted; then sudo -n umount "$work/iso" || :; fi
  if $kvm_acl; then sudo -n setfacl -x "u:$(id -un)" /dev/kvm || :; fi
  # Unique ephemeral Administrator secret exists only on this job's runner.
  [[ -f "$RUNNER_TEMP/Autounattend.xml" ]] && rm -f -- "$RUNNER_TEMP/Autounattend.xml"
  [[ "$work" == "$RUNNER_TEMP"/r104-isolated-install.* ]] && rm -rf -- "$work"
  echo R104_EPHEMERAL_ISO_VM_CREDENTIALS_AND_IMAGES_CLEANED
}
trap cleanup EXIT INT TERM
available=$(df -PB1 "$work" | awk 'NR==2{print $4}')
if (( available < 55*1024*1024*1024 ||
      $(awk '/MemAvailable:/{print $2}' /proc/meminfo) < 8*1024*1024 ||
      $(nproc) < 2 )); then
  echo R104_STOP_INADEQUATE_FREE_RUNNER_CAPACITY; exit 5
fi
sudo -n apt-get update -qq
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
  qemu-system-x86 qemu-utils ovmf acl p7zip-full wimtools genisoimage python3-evtx \
  ntfs-3g util-linux ca-certificates >/dev/null
if [[ ! -e /dev/kvm ]]; then echo R104_STOP_KVM_MISSING; exit 5; fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo -n setfacl -m "u:$(id -un):rw" /dev/kvm
  kvm_acl=true
fi
python3 - <<'PY'
import fcntl,os
fd=os.open("/dev/kvm",os.O_RDWR|os.O_CLOEXEC)
try:
    assert fcntl.ioctl(fd,0xAE00)==12
finally:
    os.close(fd)
print("R104_HOST_KVM_VERSION12_AVAILABLE")
PY
link='https://go.microsoft.com/fwlink/?clcid=0x409&country=us&culture=en-us&linkid=2345730'
url=$(curl -fSsIL --connect-timeout 20 --max-time 120 \
  --proto '=https' --proto-redir '=https' \
  -o "$work/headers.txt" -w '%{url_effective}' "$link") || {
  echo R104_STOP_OFFICIAL_EVALUATION_ISO_LINK_UNAVAILABLE; exit 5;
}
R104_URL="$url" python3 - <<'PY'
from urllib.parse import urlparse
import os
u=urlparse(os.environ["R104_URL"])
allowed={"download.microsoft.com","software-static.download.prss.microsoft.com",
         "software.download.prss.microsoft.com","software-download.microsoft.com"}
if u.scheme!="https" or u.hostname not in allowed:
    raise SystemExit("R104_REFUSED_NON_MICROSOFT_EVAL_ISO")
print("R104_MICROSOFT_HTTPS_EVALUATION_ISO_VERIFIED")
PY
curl -fLsS --retry 1 --retry-delay 3 --connect-timeout 30 --max-time 950 \
  --proto '=https' --proto-redir '=https' --max-filesize 14000000000 \
  -o "$work/windows.iso" "$url" || {
  echo R104_STOP_EVALUATION_ISO_DOWNLOAD; exit 5;
}
size=$(stat -c %s "$work/windows.iso")
if (( size < 2*1024*1024*1024 || size > 14000000000 )); then
  echo R104_STOP_ISO_SIZE_NOT_REVIEWED; exit 5
fi
mkdir -p "$work/iso"
if sudo -n mount -o loop,ro,nosuid,nodev,noexec "$work/windows.iso" "$work/iso"; then
  iso_mounted=true
else
  echo R104_STOP_READONLY_OFFICIAL_ISO_MOUNT_UNAVAILABLE; exit 5
fi
[[ -f "$work/iso/efi/boot/bootx64.efi" &&
   -f "$work/iso/sources/boot.wim" &&
   -f "$work/iso/sources/install.wim" ]] || {
  echo R104_STOP_EVAL_ISO_SETUP_PAYLOAD_MISSING; exit 5;
}
wimlib-imagex info "$work/iso/sources/install.wim" --extract-xml="$work/wim.xml" >/dev/null
index_out=$(/usr/bin/python3 -B lab/cloud-windows-r103/choose_official_wim_edition.py \
    --official-wim-xml "$work/wim.xml") || {
  echo R104_STOP_OFFICIAL_WIM_EDITION_ID_UNVERIFIABLE; exit 5;
}
image_index=$(printf '%s\n' "$index_out" | awk -F= '/^R103_WIM_EVALUATION_STANDARD_DESKTOP_IMAGE_INDEX=/ {print $2}')
[[ "$image_index" =~ ^[1-8]$ ]] || { echo R104_BAD_WIM_INDEX; exit 5; }
echo R104_VERIFIED_EVAL_STANDARD_DESKTOP_AMD64_INDEX
R104_IMAGE_INDEX="$image_index" /usr/bin/python3 -B - <<'PY'
import os,sys
from pathlib import Path
sys.path.insert(0,"lab/cloud-windows-r102")
from ephemeral_windows_answer import write_one_run_answer,ALLOWED_EDITION
write_one_run_answer(int(os.environ["R104_IMAGE_INDEX"]),
                     edition=ALLOWED_EDITION,
                     output=Path(os.environ["RUNNER_TEMP"])/"Autounattend.xml")
PY
genisoimage -quiet -J -R -V R104_ANSWER -o "$work/answer.iso" \
    -graft-points "Autounattend.xml=$RUNNER_TEMP/Autounattend.xml" >/dev/null
qemu-img create -q -f qcow2 "$work/guest.qcow2" 64G
test -r /usr/share/OVMF/OVMF_CODE_4M.fd
test -r /usr/share/OVMF/OVMF_VARS_4M.fd
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars.fd"
# This is Windows Setup's own standard SATA path (no VirtIO drivers,
# security bypasses, guest NIC, NAT, internet, SSH/RDP or public console).
r104_start=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
qemu-system-x86_64 -name R104-Free-Isolated-Microsoft-Eval \
    -machine q35,accel=kvm -cpu host -smp 2 -m 6144 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file="$work/vars.fd" \
    -device ich9-ahci,id=r104sata \
    -drive if=none,id=r104guest,file="$work/guest.qcow2",format=qcow2 \
    -device ide-hd,drive=r104guest,bus=r104sata.0,bootindex=2 \
    -drive if=none,id=r104iso,file="$work/windows.iso",format=raw,media=cdrom,readonly=on \
    -device ide-cd,drive=r104iso,bus=r104sata.1,bootindex=1 \
    -drive if=none,id=r104answer,file="$work/answer.iso",format=raw,media=cdrom,readonly=on \
    -device ide-cd,drive=r104answer,bus=r104sata.2 \
    -vga std -display none -vnc 127.0.0.1:3 -nic none \
    -qmp "unix:$work/qmp.sock,server=on,wait=off" \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    >"$work/qemu.log" 2>&1 &
pid=$!
for i in $(seq 1 30); do
  if [[ -S "$work/qmp.sock" ]] && kill -0 "$pid" 2>/dev/null; then break; fi
  sleep 1
done
[[ -S "$work/qmp.sock" ]] || {
  echo R104_WINDOWS_EVAL_INSTALL_VM_START_FAILED; exit 6;
}
echo R104_WINDOWS_EVALUATION_ISO_SETUP_VM_RUNNING_NO_NIC
# No guest-side scripts, execution-policy changes or remote shell.
# Windows Setup/OOBE is allowed to run uninterrupted in isolation.
sleep 1500
if ! kill -0 "$pid" 2>/dev/null; then
  echo R104_WINDOWS_ISO_VM_TERMINATED_EARLY; exit 6
fi
python3 -B lab/cloud-windows-r97/qmp_inspect.py "$work/qmp.sock" quit
wait "$pid" || :
pid=''
r104_end=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Native Linux host acts as an independent observer. Never mount guest
# during QEMU activity or modify guest disks through the host.
qemu-img convert -q -O raw -S 4k "$work/guest.qcow2" "$work/offline.raw"
mkdir -p "$work/mnt"
if ! /usr/bin/python3 -B lab/cloud-windows-r104/loop_readonly_system_evtx.py \
    --raw "$work/offline.raw" --mount "$work/mnt" \
    --output "$work/System.evtx"; then
  echo R104_WINDOWS_SETUP_DID_NOT_PROVE_NATIVE_OS_BOOT_DENY; exit 6
fi
if ! /usr/bin/python3 -B lab/cloud-windows-r104/windows_boot_evtx_witness.py \
    --after "$work/System.evtx" --start-utc "$r104_start" --end-utc "$r104_end"; then
  echo R104_FRESH_WINDOWS_KERNEL_AND_EVENTLOG_BOOT_NOT_CORROBORATED_DENY; exit 6
fi
echo R104_REAL_OFFICIAL_ISO_WINDOWS_KERNEL_BOOT_WITNESSED
echo R104_NATIVE_WIREGUARDNT_AND_WFP_NOT_TESTED
echo R104_GUEST_PUBLIC_NETWORK_ACCESS=false
echo R104_GA_OR_FIELD_R83_UNLOCK=false
