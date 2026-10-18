#!/usr/bin/env bash
# R99 no Windows guest: test EFI inventory against own throwaway FAT disk only.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo R99_EFI_SMOKE_REFUSED_UNTRUSTED_RUNNER; exit 4
fi
work=$(mktemp -d "${RUNNER_TEMP:?}/r99-synthetic-efi.XXXXXXXX")
disk="$work/fake-eval.raw"
mnt="$work/writemount"
dev=''
mounted=false
cleanup() {
  set +e
  if $mounted; then sudo -n umount "$mnt"; fi
  if [[ -n "$dev" && "$dev" =~ ^/dev/loop[0-9]+$ ]]; then
    if [[ "$(sudo -n losetup -l -n -O BACK-FILE "$dev" 2>/dev/null)" == "$disk" ]]; then
      sudo -n losetup -d "$dev" || :
    fi
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM
sudo -n apt-get update -qq
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends dosfstools util-linux parted >/dev/null
truncate -s 3G "$disk"
printf 'label: dos\nsize=131072, type=c\n' | sudo -n sfdisk -q "$disk"
dev=$(sudo -n losetup --find --show --partscan "$disk")
[[ "$dev" =~ ^/dev/loop[0-9]+$ ]] || exit 6
part="${dev}p1"
for i in {1..10}; do [[ -b "$part" ]] && break; sleep 0.2; done
[[ -b "$part" ]] || { echo R99_EFI_SYNTH_PARTITION_MISSING; exit 6; }
sudo -n mkfs.vfat -F 32 "$part" >/dev/null
mkdir -p "$mnt"
sudo -n mount -t vfat "$part" "$mnt"
mounted=true
sudo -n mkdir -p "$mnt/EFI/Microsoft/Boot" "$mnt/EFI/Boot"
# Dummy zero bytes are not Microsoft files! Test only the parser's
# existence checks, not OS boot, cryptographic signatures or authentication.
sudo -n dd if=/dev/zero of="$mnt/EFI/Microsoft/Boot/bootmgfw.efi" bs=1024 count=2 status=none
sudo -n dd if=/dev/zero of="$mnt/EFI/Microsoft/Boot/BCD" bs=1024 count=2 status=none
sudo -n dd if=/dev/zero of="$mnt/EFI/Boot/bootx64.efi" bs=1024 count=2 status=none
sudo -n umount "$mnt"
mounted=false
sudo -n losetup -d "$dev"
dev=''
mkdir -p "$work/readmount"
python3 -B lab/cloud-windows-r99/inspect_windows_vhd_efi_ro.py --raw "$disk" --mount "$work/readmount" >"$work/report"
for mark in R99_EFI_MICROSOFT_BOOTMGR_PRESENT=true R99_EFI_MICROSOFT_BCD_PRESENT=true R99_EFI_FALLBACK_BOOTX64_PRESENT=true; do
  if ! grep -Fqx "$mark" "$work/report"; then
    echo R99_EFI_SYNTHETIC_FIXTURE_READER_FAILED; exit 6
  fi
done
echo R99_SYNTHETIC_READONLY_EFI_INVENTORY_PASS
echo R99_REAL_MICROSOFT_EFI_SIGNATURE_VERIFIED=false
echo R99_REAL_WINDOWS_BOOT_VERIFIED=false
