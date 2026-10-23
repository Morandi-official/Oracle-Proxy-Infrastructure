"""R102: generate *only* an ephemeral, no-network Windows evaluation answer file.

Source-review and synthetic tests only. This tool does NOT install Windows,
launch QEMU, run scripts, alter WFP, create users on a real computer, or
download ISO. Future use restricted to isolated PUBLIC standard GH runners.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import tempfile
import xml.etree.ElementTree as ET

U = "urn:schemas-microsoft-com:unattend"
WCM = "http://schemas.microsoft.com/WMIConfig/2002/State"
ET.register_namespace("", U)
ET.register_namespace("wcm", WCM)
NS = lambda name: "{" + U + "}" + name

ALLOWED_EDITION = "Windows Server 2025 Standard Evaluation (Desktop Experience)"
MAX_INDEX = 8


class UnsafeAnswerFile(ValueError):
    pass


def _element(parent: ET.Element, name: str, value: str | None = None,
             action: str | None = None) -> ET.Element:
    attributes = {"{" + WCM + "}action": action} if action else {}
    node = ET.SubElement(parent, NS(name), attributes)
    if value is not None:
        node.text = value
    return node


def _component(settings: ET.Element, name: str) -> ET.Element:
    return ET.SubElement(settings, NS("component"), {
        "name": name,
        "processorArchitecture": "amd64",
        "publicKeyToken": "31bf3856ad364e35",
        "language": "neutral",
        "versionScope": "nonSxS",
    })


def generate(index: int, *, edition: str) -> tuple[bytes, str]:
    # The caller must independently prove the index from the downloaded,
    # official Microsoft ISO install.wim, not a PR field or user-supplied JSON.
    if type(index) is not int or index < 1 or index > MAX_INDEX or (
            edition != ALLOWED_EDITION):
        raise UnsafeAnswerFile("unreviewed Windows evaluation image selection")
    # Strictly random, one-run local Administrator secret. Never print,
    # persist to repo/artifact/cache, embed in workflow YAML or reuse in GA.
    password = "A7!" + secrets.token_urlsafe(36)
    root = ET.Element(NS("unattend"))
    pe = _element(root, "settings")
    pe.set("pass", "windowsPE")
    loc = _component(pe, "Microsoft-Windows-International-Core-WinPE")
    lang = _element(loc, "SetupUILanguage")
    _element(lang, "UILanguage", "en-US")
    for key in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        _element(loc, key, "en-US")
    setup = _component(pe, "Microsoft-Windows-Setup")
    disk_conf = _element(setup, "DiskConfiguration")
    disk = _element(disk_conf, "Disk", action="add")
    _element(disk, "DiskID", "0")
    _element(disk, "WillWipeDisk", "true")
    parts = _element(disk, "CreatePartitions")
    for order, kind, size in ((1, "EFI", "260"), (2, "MSR", "16"),
                              (3, "Primary", None)):
        part = _element(parts, "CreatePartition", action="add")
        _element(part, "Order", str(order))
        _element(part, "Type", kind)
        if size is not None:
            _element(part, "Size", size)
        else:
            _element(part, "Extend", "true")
    modify = _element(disk, "ModifyPartitions")
    for order, partno, fmt, name in (
        (1, 1, "FAT32", "SYSTEM"),
        (2, 3, "NTFS", "WINDOWS"),
    ):
        part = _element(modify, "ModifyPartition", action="add")
        _element(part, "Order", str(order))
        _element(part, "PartitionID", str(partno))
        _element(part, "Format", fmt)
        _element(part, "Label", name)
    osimage = _element(_element(setup, "ImageInstall"), "OSImage")
    metadata = _element(_element(osimage, "InstallFrom"), "MetaData", action="add")
    _element(metadata, "Key", "/IMAGE/INDEX")
    _element(metadata, "Value", str(index))
    dest = _element(osimage, "InstallTo")
    _element(dest, "DiskID", "0")
    _element(dest, "PartitionID", "3")
    _element(osimage, "WillShowUI", "OnError")
    _element(_element(setup, "UserData"), "AcceptEula", "true")

    oobe = _element(root, "settings")
    oobe.set("pass", "oobeSystem")
    shell = _component(oobe, "Microsoft-Windows-Shell-Setup")
    _element(shell, "TimeZone", "UTC")
    secret = _element(_element(shell, "UserAccounts"), "AdministratorPassword")
    _element(secret, "Value", password)
    _element(secret, "PlainText", "true")
    # No AutoLogon, RunSynchronous, FirstLogonCommands, PowerShell,
    # TPM/security bypass, domain join, driver, guest NIC or product key.
    return ET.tostring(root, encoding="utf-8", xml_declaration=True), password


def write_one_run_answer(index: int, *, edition: str, output: Path) -> None:
    runner = os.environ.get("RUNNER_TEMP", "")
    if not runner:
        raise UnsafeAnswerFile("no isolated GH runner temp")
    directory = Path(runner).resolve()
    target = output.resolve()
    if target.parent != directory or target.name != "Autounattend.xml" or (
            target.exists() or target.is_symlink()):
        raise UnsafeAnswerFile("answer file outside exact empty ephemeral location")
    if os.environ.get("GITHUB_ACTIONS") != "true" or (
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted") or (
            os.environ.get("RUNNER_OS") != "Linux"):
        raise UnsafeAnswerFile("outside isolated GH hosted Linux")
    xml, secret = generate(index, edition=edition)
    # Only the file stores the ephemeral plaintext secret; never stdout.
    fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(xml)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    finally:
        del secret
    print("R102_EPHEMERAL_WINDOWS_EVAL_ANSWER_CREATED_FOR_ISOLATED_CI_ONLY")
    print("R102_NIC_DRIVER_WFP_AND_PRODUCT_INSTALL_NOT_AUTHORIZED_BY_ANSWER")


if __name__ == "__main__":
    raise SystemExit("R102 source-only; no generic CLI or install action")
