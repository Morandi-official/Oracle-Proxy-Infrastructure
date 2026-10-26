"""Host-only allocation heuristic for the disposable R104 QEMU disk.

An increased sparse QCOW2 allocation is NOT proof Windows ran or installed.
This function receives only numeric host stat(2) metadata, not guest contents.
"""
from __future__ import annotations
import argparse

MIN_CHECK_MINUTE = 12
MIN_PROGRESS_512_BLOCKS = (8 * 1024 * 1024) // 512


def classify(initial_blocks: int, peak_blocks: int, elapsed_minutes: int) -> str:
    for x in (initial_blocks, peak_blocks, elapsed_minutes):
        if type(x) is not int or x < 0:
            return "R104_INVALID_HOST_DISK_METADATA_DENY"
    if peak_blocks < initial_blocks or elapsed_minutes > 25:
        return "R104_INVALID_HOST_DISK_METADATA_DENY"
    if elapsed_minutes < MIN_CHECK_MINUTE:
        return "R104_HOST_ALLOCATION_OBSERVING_NOT_WINDOWS_PROOF"
    if peak_blocks - initial_blocks < MIN_PROGRESS_512_BLOCKS:
        return "R104_HOST_DISK_ALLOCATION_STALLED_DENY"
    return "R104_HOST_DISK_ALLOCATION_PROGRESS_NOT_WINDOWS_BOOT_PROOF"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--initial-blocks", required=True, type=int)
    p.add_argument("--peak-blocks", required=True, type=int)
    p.add_argument("--elapsed-minutes", required=True, type=int)
    args = p.parse_args()
    result = classify(args.initial_blocks, args.peak_blocks, args.elapsed_minutes)
    print(result)
    return 6 if result.endswith("_DENY") else 0


if __name__ == "__main__":
    raise SystemExit(main())
