#!/usr/bin/env bash
# Public-repository standard hosted runner, zero paid resources.
# Trial: official Microsoft Windows Server evaluation VHD; isolated QEMU disk
# reset and rollback only. No guest networks, VPN, WFP or user PC operations.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true ||
      "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${GITHUB_REPOSITORY:-}" != Morandi-official/Oracle-Proxy-Infrastructure ||
      "${GITHUB_EVENT_NAME:-}" != pull_request ]]; then
  echo R97_REFUSED_NOT_EXACT_PUBLIC_STANDARD_RUNNER; exit 4
fi
# Trusted GitHub runner event payload is locally supplied for this job.
# Avoid anonymous GitHub API throttling and never use caller-controlled values.
if ! python3 - "$GITHUB_EVENT_PATH" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1]))
repo=obj.get("repository",{})
pr=obj.get("pull_request",{})
assert repo.get("full_name") == "Morandi-official/Oracle-Proxy-Infrastructure"
assert repo.get("private") is False
assert repo.get("visibility") == "public"
assert pr.get("head",{}).get("repo",{}).get("full_name") == repo["full_name"]
assert pr.get("head",{}).get("ref") == "test/r97-free-qemu-windows-evaluation-boot-20261018"
PY
then
  echo R97_STOP_TRUSTED_PUBLIC_REPOSITORY_EVENT_NOT_VERIFIED; exit 4
fi
echo R97_FREE_PUBLIC_STANDARD_RUNNER_CONFIRMED
work=$(mktemp -d "$RUNNER_TEMP/r97-ephemeral.XXXXXXXX")
if [[ "$work" != "$RUNNER_TEMP"/r97-ephemeral.* ]]; then exit 4; fi
qpid=''
acl=false
cleanup() {
  set +e
  if [[ -n "$qpid" ]]; then kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null; fi
  if $acl; then sudo -n setfacl -x "u:$(id -un)" /dev/kvm >/dev/null 2>&1 || :; fi
  if [[ -d "$work" && "$work" == "$RUNNER_TEMP"/r97-ephemeral.* ]]; then rm -rf -- "$work"; fi
  echo R97_NO_PERSISTED_IMAGE_ARTIFACT_OR_CACHE
}
trap cleanup EXIT INT TERM
if [[ ! -e /dev/kvm ]] ||
   (( $(df -PB1 "$work" | awk 'NR==2{print $4}') < 45*1024*1024*1024 )) ||
   (( $(awk '/MemAvailable:/{print $2}' /proc/meminfo) < 8*1024*1024 )) ||
   (( $(nproc) < 2 )); then
  echo R97_STOP_FREE_RUNNER_RESOURCES_NOT_SUITABLE; exit 5
fi
sudo -n apt-get update -qq
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
  --no-install-recommends qemu-system-x86 qemu-utils ovmf acl unzip file >/dev/null
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo -n setfacl -m "u:$(id -un):rw" /dev/kvm
  acl=true
fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo R97_STOP_HOSTED_KVM_INACCESSIBLE; exit 5
fi
# Link on Microsoft's public evaluation-center download page (English VHD).
link='https://go.microsoft.com/fwlink/?clcid=0x804&country=cn&culture=zh-cn&linkid=2345826'
source=$(curl -fsSIL --connect-timeout 20 --max-time 100 \
  --proto '=https' --proto-redir '=https' \
  -o "$work/headers" -w '%{url_effective}' "$link") || {
  echo R97_STOP_OFFICIAL_MICROSOFT_DOWNLOAD_LINK_UNAVAILABLE; exit 5;
}
R97_SOURCE="$source" python3 - <<'PY'
import os
from urllib.parse import urlparse
u = urlparse(os.environ["R97_SOURCE"])
allowed = {"download.microsoft.com", "software-static.download.prss.microsoft.com",
           "software.download.prss.microsoft.com", "software-download.microsoft.com"}
if u.scheme != "https" or u.hostname not in allowed:
    raise SystemExit("R97_STOP_MICROSOFT_IMAGE_ORIGIN_NOT_VERIFIED")
print("R97_OFFICIAL_MICROSOFT_EVAL_DOWNLOAD_ORIGIN_PASS")
PY
curl -fLsS --retry 1 --retry-delay 3 --connect-timeout 20 \
  --max-time 900 --max-filesize 18000000000 \
  --proto '=https' --proto-redir '=https' \
  -o "$work/downloaded" "$source" || {
  echo R97_STOP_OFFICIAL_DOWNLOAD_FAILED_WITHOUT_PAID_FALLBACK; exit 5;
}
size=$(stat -c %s "$work/downloaded")
if (( size < 512*1024*1024 || size > 18000000000 )); then
  echo R97_STOP_BAD_WINDOWS_EVAL_IMAGE_SIZE; exit 5
fi
echo R97_OFFICIAL_WINDOWS_EVAL_IMAGE_DOWNLOADED_TO_TEMPORARY_RUNNER_ONLY
base="$work/microsoft-eval.vhd"
if [[ "$(file -b "$work/downloaded")" == *"Zip archive"* ]]; then
  mapfile -t image_entries < <(unzip -Z1 "$work/downloaded" | grep -Ei '\.(vhd|vhdx)$' || :)
  if (( ${#image_entries[@]} != 1 )) || [[ "${image_entries[0]}" == /* ]] ||
      [[ "${image_entries[0]}" == *../* ]]; then
    echo R97_STOP_UNREVIEWED_EVAL_ARCHIVE; exit 5
  fi
  unzip -p "$work/downloaded" "${image_entries[0]}" > "$base"
  rm -f -- "$work/downloaded"
else
  mv "$work/downloaded" "$base"
fi
qemu-img info --output=json "$base" > "$work/disk.json"
fmt=$(python3 - "$work/disk.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
f=d.get("format")
if f not in ("vpc","vhdx","raw") or not 2*1024**3 < d.get("virtual-size",0) < 200*1024**3:
    raise SystemExit("R97_STOP_EVAL_DISK_FORMAT_OR_SIZE_UNKNOWN")
print(f)
PY
)
test -r /usr/share/OVMF/OVMF_CODE_4M.fd
test -r /usr/share/OVMF/OVMF_VARS_4M.fd
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars.fd"
qemu-img create -q -f qcow2 -F "$fmt" -b "$base" "$work/overlay.qcow2"
echo R97_READONLY_BASE_AND_DISPOSABLE_COW_DISK_CREATED
launch() {
  local slot=${1:-A}
  local vnc_display=2
  if [[ "$slot" == B ]]; then vnc_display=3; fi
  rm -f -- "$work/qmp.sock"
  qemu-system-x86_64 -name R97-isolated-eval -machine q35,accel=kvm \
    -cpu host -smp 2 -m 6144 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file="$work/vars.fd" \
    -drive file="$work/overlay.qcow2",format=qcow2,if=ide \
    -vga std -display none -vnc "127.0.0.1:$vnc_display" -nic none \
    -qmp "unix:$work/qmp.sock,server=on,wait=off" \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    > "$work/qemu.log" 2>&1 &
  qpid=$!
  for i in $(seq 1 30); do
    if [[ -S "$work/qmp.sock" ]] && kill -0 "$qpid" 2>/dev/null; then return; fi
    sleep 1
  done
  echo R97_QEMU_LOCAL_ONLY_STARTUP_DIAGNOSTICS_BEGIN
  if [[ -f "$work/qemu.log" ]]; then
    # Print only QEMU errors; do not upload screenshots, disks or secrets.
    tail -n 12 "$work/qemu.log" | sed -E 's@/home/runner/[^ ]+@<RUNNER_PATH>@g'
  fi
  echo R97_STOP_QEMU_FAILED_TO_LAUNCH; exit 5
}
stop() {
  python3 lab/cloud-windows-r97/qmp_inspect.py "$work/qmp.sock" quit
  wait "$qpid" || :
  qpid=''
}
launch A
sleep 110
python3 lab/cloud-windows-r97/qmp_inspect.py "$work/qmp.sock" screenshot "$work/first.ppm"
echo R97_GUEST_GFX_RESPONDS_NO_WINDOWS_LOGIN_PROOF
python3 lab/cloud-windows-r97/qmp_inspect.py "$work/qmp.sock" reset
sleep 50
python3 lab/cloud-windows-r97/qmp_inspect.py "$work/qmp.sock" screenshot "$work/reset.ppm"
stop
rm -f -- "$work/overlay.qcow2"
qemu-img create -q -f qcow2 -F "$fmt" -b "$base" "$work/overlay.qcow2"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$work/vars.fd"
echo R97_EXTERNAL_HOST_DISK_ROLLBACK_PASS
sleep 3
launch B
sleep 50
python3 lab/cloud-windows-r97/qmp_inspect.py "$work/qmp.sock" screenshot "$work/restored.ppm"
stop
echo R97_HOST_QEMU_RESET_AND_OVERLAY_ROLLBACK_COMPLETE
echo R97_WINDOWS_KERNEL_BOOT_NOT_INDEPENDENTLY_PROVEN
echo R97_REAL_WINDOWS_IN_GUEST_REBOOT_NOT_TESTED
echo R97_WFP_VPN_UU_NOT_TESTED
echo R97_NO_GUEST_NETWORK_AND_NO_PAID_FEATURES
