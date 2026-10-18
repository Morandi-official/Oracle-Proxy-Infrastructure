"""R103 strictly select an authentic-looking, bounded WIM metadata IMAGE/INDEX.

This is necessary but never sufficient: the caller MUST separately prove the
ISO is the official Microsoft Evaluation Center image as R101 does. No
download, Windows install, guest network, signing, driver or WFP operation.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import xml.etree.ElementTree as ET

EXPECTED_DISPLAY = "Windows Server 2025 Standard Evaluation (Desktop Experience)"
ALLOWED_EDITION_IDS = frozenset({"ServerStandardEval", "ServerStandard"})
MAX_METADATA_BYTES = 1_048_576
MAX_IMAGES = 8


class ImageSelectionRefused(ValueError):
    pass


def select_index(data: bytes) -> int:
    if (type(data) is not bytes or not 12 <= len(data) <= MAX_METADATA_BYTES):
        raise ImageSelectionRefused("untrusted WIM metadata size")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ImageSelectionRefused("malformed WIM XML") from e
    if root.tag != "WIM":
        raise ImageSelectionRefused("not a standard WIM XML document")
    images = root.findall("./IMAGE")
    if not 1 <= len(images) <= MAX_IMAGES:
        raise ImageSelectionRefused("unbounded or missing WIM images")
    matches = []
    used_indices = set()
    for image in images:
        raw_index = image.get("INDEX", "")
        if not re.fullmatch(r"[1-8]", raw_index):
            raise ImageSelectionRefused("invalid WIM image index")
        index = int(raw_index)
        if index in used_indices:
            raise ImageSelectionRefused("duplicate WIM image index")
        used_indices.add(index)
        if image.findtext("DISPLAYNAME", default="") != EXPECTED_DISPLAY:
            continue
        if image.findtext("WINDOWS/EDITIONID", default="") not in ALLOWED_EDITION_IDS:
            raise ImageSelectionRefused("displayed evaluation edition mismatch")
        if image.findtext("WINDOWS/ARCH", default="") != "9":
            raise ImageSelectionRefused("evaluation image architecture not AMD64")
        matches.append(index)
    if len(matches) != 1:
        raise ImageSelectionRefused("evaluation desktop image not uniquely proven")
    return matches[0]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--official-wim-xml", type=Path, required=True)
    args = p.parse_args()
    try:
        path = args.official_wim_xml
        if not path.is_file() or path.is_symlink():
            raise ImageSelectionRefused("unverified metadata source file")
        if path.stat().st_size > MAX_METADATA_BYTES:
            raise ImageSelectionRefused("metadata exceeds bound")
        index = select_index(path.read_bytes())
        # A number is not a trust root: R101 official HTTPS media check MUST
        # have happened independently in the same ephemeral CI job.
        print("R103_WIM_EVALUATION_STANDARD_DESKTOP_IMAGE_INDEX=" + str(index))
        print("R103_METADATA_ONLY_NOT_BOOT_INSTALL_OR_DRIVER_APPROVAL")
    except (OSError, ImageSelectionRefused) as e:
        # Do not print arbitrary WIM values or source filenames.
        print("R103_WIM_IMAGE_SELECTION_DENIED_" + type(e).__name__)
        raise SystemExit(6)


if __name__ == "__main__":
    main()
