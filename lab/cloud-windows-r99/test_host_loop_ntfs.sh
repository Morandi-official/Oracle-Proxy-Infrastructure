#!/usr/bin/env bash
# Host-only synthetic NTFS read-only loop test. No Windows disk touched.
set -Eeuo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_OS:-}" != Linux ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo R99_REFUSED_NON_HOSTED_ENVIRONMENT; exit 4
fi
scratch=$(mktemp -d "${RUNNER_TEMP:?}/r99-loopcheck.XXXXXXXX")
image="$scratch/synthetic.raw"
mnt="$scratch/mnt"
device=''
mounted=false
cleanup() {
  set +e
  if $mounted; then sudo -n umount "$mnt"; fi
  if [[ -n "$device" ]]; then
    owner=$(sudo -n losetup -l -n -O BACK-FILE "$device" 2>/dev/null)
    if [[ "$owner" == "$image" ]]; then sudo -n losetup -d "$device"; fi
  fi
  rm -rf -- "$scratch"
}
trap cleanup EXIT INT TERM
sudo -n apt-get update -qq
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends util-linux kmod ntfs-3g parted >/dev/null
truncate -s 128M "$image"
printf 'label: dos\nsize=200000, type=7\n' | sudo -n sfdisk -q "$image"
if ! device=$(sudo -n losetup --find --show --partscan "$image"); then
  echo R99_NO_SYNTHETIC_LINUX_LOOP_DEVICE_AVAILABLE; exit 6
fi
[[ "$device" =~ ^/dev/loop[0-9]+$ ]] || exit 6
part="${device}p1"
for i in {1..10}; do [[ -b "$part" ]] && break; sleep 0.2; done
if [[ ! -b "$part" ]]; then
  echo R99_LOOP_PARTITION_SCAN_UNAVAILABLE; exit 6
fi
sudo -n mkfs.ntfs -F -Q "$part" >/dev/null
sudo -n losetup -d "$device"
device=''
device=$(sudo -n losetup --find --show --partscan --read-only "$image")
part="${device}p1"
mkdir -p "$mnt"
if sudo -n mount -t ntfs3 -o ro "$part" "$mnt" 2>/dev/null; then
  mounted=true
elif sudo -n mount -t ntfs-3g -o ro "$part" "$mnt" 2>/dev/null; then
  mounted=true
else
  echo R99_SYNTHETIC_NTFS_READONLY_MOUNT_UNAVAILABLE; exit 6
fi
fs=$(findmnt -n -o FSTYPE --target "$mnt")
if [[ "$fs" != ntfs3 && "$fs" != fuseblk ]]; then
  echo R99_SYNTHETIC_NTFS_MOUNT_INVALID; exit 6
fi
echo R99_SYNTHETIC_NTFS_HOST_READONLY_MOUNT_PASS
sudo -n umount "$mnt"
mounted=false
owner=$(sudo -n losetup -l -n -O BACK-FILE "$device")
[[ "$owner" == "$image" ]] || { echo R99_FOREIGN_LOOP_DEVICE_REFUSED; exit 6; }
sudo -n losetup -d "$device"
device=''
echo R99_EXACT_LOOP_UNMOUNT_DETACH_PASS
echo R99_REAL_WINDOWS_BOOT_VERIFIED=false
echo R99_GUEST_DRIVER_WFP_TESTED=false
