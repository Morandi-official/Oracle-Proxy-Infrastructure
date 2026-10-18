#!/usr/bin/env bash
# R101 official free Microsoft Evaluation Center ISO source + UEFI metadata.
# NO Windows installation, VM boot, user PC, VPN/WFP/Oracle or paid services.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${GITHUB_REPOSITORY:-}" != Morandi-official/Oracle-Proxy-Infrastructure ||
      "${GITHUB_EVENT_NAME:-}" != pull_request ]]; then
  echo R101_REFUSED_NOT_FREE_PUBLIC_GH_PR; exit 4
fi
python3 - "$GITHUB_EVENT_PATH" <<'PY'
import json,sys
e=json.load(open(sys.argv[1]))
r=e["repository"]
h=e["pull_request"]["head"]
assert r["full_name"]=="Morandi-official/Oracle-Proxy-Infrastructure"
assert r["private"] is False and r["visibility"]=="public"
assert h["repo"]["full_name"]==r["full_name"]
assert h["ref"]=="test/r101-official-free-windows-iso-preflight-20261018"
PY
work=$(mktemp -d "${RUNNER_TEMP:?}/r101-official-iso.XXXXXXXX")
[[ "$work" == "$RUNNER_TEMP"/r101-official-iso.* ]] || exit 4
trap 'rm -rf -- "$work"' EXIT
free_space=$(df -PB1 "$work" | awk 'NR==2 {print $4}')
if (( free_space < 32*1024*1024*1024 )); then
  echo R101_STOP_INSUFFICIENT_FREE_RUNNER_STORAGE; exit 5
fi
sudo -n apt-get update -qq
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends p7zip-full file ca-certificates >/dev/null
# The exact English ISO link on Microsoft Evaluation Center, no third-party mirrors.
source='https://go.microsoft.com/fwlink/?clcid=0x409&country=us&culture=en-us&linkid=2345730'
final=$(curl -fSsIL --connect-timeout 20 --max-time 120 \
  --proto '=https' --proto-redir '=https' -o "$work/headers.txt" \
  -w '%{url_effective}' "$source") || {
  echo R101_STOP_OFFICIAL_ISO_LINK_HEAD_UNAVAILABLE; exit 5;
}
R101_FINAL="$final" python3 - <<'PY'
from urllib.parse import urlparse
import os
url=urlparse(os.environ["R101_FINAL"])
allow={"download.microsoft.com","software-static.download.prss.microsoft.com",
       "software.download.prss.microsoft.com","software-download.microsoft.com"}
if url.scheme!="https" or url.hostname not in allow:
    raise SystemExit("R101_REFUSED_UNEXPECTED_EVALUATION_ISO_ORIGIN")
print("R101_MICROSOFT_DIRECT_HTTPS_ISO_ORIGIN_VERIFIED")
PY
# Temporary media only. Do not publish it or upload artifact/cache/custom image.
curl -fLsS --retry 1 --retry-delay 3 --connect-timeout 30 --max-time 900 \
  --proto '=https' --proto-redir '=https' --max-filesize 14000000000 \
  -o "$work/windows-eval.iso" "$final" || {
  echo R101_STOP_OFFICIAL_EVALUATION_ISO_DOWNLOAD_FAILED; exit 5;
}
size=$(stat -c %s "$work/windows-eval.iso")
if (( size < 2*1024*1024*1024 || size > 14000000000 )); then
  echo R101_STOP_WINDOWS_EVALUATION_ISO_SIZE_OUT_OF_BOUNDS; exit 5
fi
# Do not execute ISO content. Just inspect UEFI and installer archive entries.
7z l -slt "$work/windows-eval.iso" > "$work/iso-list.txt" || {
  echo R101_STOP_WINDOWS_EVALUATION_MEDIA_FORMAT_UNRECOGNIZED; exit 5;
}
python3 - "$work/iso-list.txt" <<'PY'
import sys
lines=open(sys.argv[1],encoding="utf-8",errors="replace").read().splitlines()
names={line[7:].strip().lower().replace("\\","/").removeprefix("/")
       for line in lines if line.startswith("Path = ")}
uefi="efi/boot/bootx64.efi" in names
setup="sources/boot.wim" in names
install=any(f in names for f in ("sources/install.wim","sources/install.esd"))
print("R101_EFI_X64_BOOT_FILE_PRESENT="+str(uefi).lower())
print("R101_WINDOWS_SETUP_BOOT_WIM_PRESENT="+str(setup).lower())
print("R101_WINDOWS_INSTALL_PAYLOAD_PRESENT="+str(install).lower())
if not (uefi and setup and install):
    raise SystemExit("R101_WINDOWS_EVALUATION_ISO_MEDIA_LAYOUT_UNVERIFIED")
print("R101_OFFICIAL_EVALUATION_ISO_MEDIA_LAYOUT_READY_NO_GUEST_BOOT")
PY
echo R101_WINDOWS_EVAL_ISO_GUEST_INSTALLED=false
echo R101_WINDOWS_KERNEL_BOOTED=false
echo R101_DRIVER_WFP_VPN_TESTED=false
echo R101_WINDOWS_CLIENT_WIRESOCK_UU_TESTED=false
echo R101_PAID_CLOUD_OR_LICENSE_PURCHASED=false
echo R101_GA_OR_R83_UNLOCK=false
