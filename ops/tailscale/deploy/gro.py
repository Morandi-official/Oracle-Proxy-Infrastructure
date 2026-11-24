"""Explicit, owned Tailscale UDP GRO forwarding on the primary Oracle NIC."""

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


DEVICE = "enp0s6"
SYSFS = Path("/sys/class/net") / DEVICE
PROFILE = Path("/etc/oracle-proxy-control/tailscale.json")
STATE = Path("/var/lib/oracle-project-ops/tailscale-gro.json")
LOCK = STATE.with_suffix(".lock")
SCRIPT = Path("/usr/local/libexec/oracle-proxy-tailnet/gro.py")
SERVICE = "oracle-proxy-tailnet-gro.service"
UNIT = Path("/etc/systemd/system") / SERVICE
ETH = "/usr/sbin/ethtool"
FORWARDING = "rx-udp-gro-forwarding"
GRO_LIST = "rx-gro-list"
GENERIC = "generic-receive-offload"
UNIT_BODY = b"""[Unit]
Description=Oracle Proxy owned Tailscale UDP GRO forwarding
Wants=network-online.target
After=network-online.target
Before=oracle-proxy-tailnet-exit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I /usr/local/libexec/oracle-proxy-tailnet/gro.py apply
ExecStop=/usr/bin/python3 -I /usr/local/libexec/oracle-proxy-tailnet/gro.py restore
TimeoutStartSec=25
TimeoutStopSec=25
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/var/lib/oracle-project-ops/tailscale-gro.lock

[Install]
WantedBy=multi-user.target
"""


def run(*argv, check=True, timeout=6):
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "LC_ALL": "C"})


def root_path(path, *, secret=False, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if secret else 0o022):
        raise ValueError("TAILNET_GRO_UNTRUSTED_FILE")
    return path


@contextmanager
def locked():
    root_path(STATE.parent, secret=True, directory=True)
    fd = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("TAILNET_GRO_UNTRUSTED_LOCK")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def write(path, data, mode):
    root_path(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        root_path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tailnet-gro-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def fingerprint():
    mac = (SYSFS / "address").read_text().strip()
    device = (SYSFS / "device").resolve(strict=True)
    pci = next((part for part in reversed(device.parts)
                if re.fullmatch(r"[a-f0-9]{4}:[a-f0-9]{2}:[a-f0-9]{2}\.[0-7]", part)), None)
    if (not device.is_relative_to("/sys/devices") or pci is None
            or not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac)):
        raise ValueError("TAILNET_GRO_PHYSICAL_IDENTITY_UNVERIFIED")
    return hashlib.sha256(f"{DEVICE}:{pci}:{mac}".encode()).hexdigest()


def check_forwarding_path():
    profile = root_path(PROFILE, secret=True)
    if profile.stat().st_size > 4096:
        raise ValueError("TAILNET_GRO_PROFILE_UNVERIFIED")
    value = json.loads(profile.read_bytes())
    if not isinstance(value, dict) or value.get("coordinator") != "https://vpn-admin.morandi.dpdns.org":
        raise ValueError("TAILNET_GRO_PROFILE_UNVERIFIED")
    version = re.match(r"(\d+)\.(\d+)", os.uname().release)
    if not version or tuple(map(int, version.groups())) < (6, 2):
        raise ValueError("TAILNET_GRO_KERNEL_UNSUPPORTED")
    for family, target in (("-4", "1.1.1.1"), ("-6", "2606:4700:4700::1111")):
        rows = json.loads(run("/usr/sbin/ip", "-j", family, "route", "get", target).stdout)
        if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("dev") != DEVICE:
            raise ValueError("TAILNET_GRO_PHYSICAL_ROUTE_UNVERIFIED")


def observed():
    output = run(ETH, "-k", DEVICE).stdout
    if len(output) > 32768:
        raise ValueError("TAILNET_GRO_FEATURE_OUTPUT_UNVERIFIED")
    flags = {}
    for row in output.splitlines():
        if match := re.match(r"\s*(generic-receive-offload|rx-udp-gro-forwarding|rx-gro-list):", row):
            option = match[1]
            state = re.fullmatch(r"\s*[a-z0-9-]+:\s+(on|off)(?:\s+(\[fixed\]))?\s*", row)
            if state is None or option in flags:
                raise ValueError("TAILNET_GRO_FEATURE_STATE_UNVERIFIED")
            flags[option] = (state[1] == "on", bool(state[2]))
    if set(flags) != {GENERIC, FORWARDING, GRO_LIST}:
        raise ValueError("TAILNET_GRO_FEATURE_UNSUPPORTED")
    return flags


def baseline():
    root_path(STATE, secret=True)
    if STATE.stat().st_size > 512:
        raise ValueError("TAILNET_GRO_BASELINE_UNVERIFIED")
    receipt = json.loads(STATE.read_bytes())
    digest = receipt.get("script_sha256") if isinstance(receipt, dict) else None
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("TAILNET_GRO_BASELINE_UNVERIFIED")
    expected = {"schema": 1, "device": DEVICE, "fingerprint": fingerprint(),
                "original": {FORWARDING: False, GRO_LIST: False}, "script_sha256": digest}
    if receipt != expected:
        raise ValueError("TAILNET_GRO_BASELINE_UNVERIFIED")
    return expected


def settings(flags, *, applying):
    if flags[GRO_LIST][0]:
        raise ValueError("TAILNET_GRO_LIST_EXTERNAL_CHANGE")
    enabled, fixed = flags[FORWARDING]
    if fixed and enabled != applying:
        raise ValueError("TAILNET_GRO_FORWARDING_FIXED")
    if applying and not flags[GENERIC][0]:
        raise ValueError("TAILNET_GRO_GENERIC_OFF")
    return enabled


def change(desired):
    baseline()
    before = observed()
    current = settings(before, applying=desired)
    if current == desired:
        return
    try:
        result = run(ETH, "-K", DEVICE, FORWARDING, "on" if desired else "off", check=False)
        final = observed()
        if (result.returncode or settings(final, applying=desired) != desired
                or final[GENERIC] != before[GENERIC] or final[GRO_LIST] != before[GRO_LIST]):
            raise ValueError("TAILNET_GRO_FEATURE_READBACK_MISMATCH")
    except (OSError, ValueError, subprocess.SubprocessError):
        baseline()
        if observed()[FORWARDING][0] != current:
            run(ETH, "-K", DEVICE, FORWARDING, "on" if current else "off")
        if observed()[FORWARDING][0] != current:
            raise ValueError("TAILNET_GRO_FAILED_CHANGE_ROLLBACK")
        raise


def activate():
    with locked():
        check_forwarding_path()
        change(True)
    print("PROJECT_TAILSCALE_GRO=VERIFIED_FORWARDING_ON")


def restore():
    with locked():
        change(False)
    print("PROJECT_TAILSCALE_GRO=VERIFIED_ORIGINAL_FLAGS")


def verify_owned_installation(receipt):
    for path in (UNIT, SCRIPT):
        if path.exists() or path.is_symlink():
            root_path(path)
    if UNIT.exists() and UNIT.read_bytes() != UNIT_BODY:
        raise ValueError("TAILNET_GRO_FOREIGN_UNIT")
    if SCRIPT.exists() and (receipt is None or SCRIPT.stat().st_size > 131072
                            or hashlib.sha256(SCRIPT.read_bytes()).hexdigest() != receipt["script_sha256"]):
        raise ValueError("TAILNET_GRO_FOREIGN_SCRIPT")


def install():
    with locked():
        check_forwarding_path()
        receipt = baseline() if STATE.exists() or STATE.is_symlink() else None
        verify_owned_installation(receipt)
        flags = observed()
        enabled = settings(flags, applying=True)
        script = Path(__file__).read_bytes()
        digest = hashlib.sha256(script).hexdigest()
        if receipt is None:
            if UNIT.exists() or SCRIPT.exists():
                raise ValueError("TAILNET_GRO_FOREIGN_DEPLOYMENT")
            if enabled:
                print("PROJECT_TAILSCALE_GRO=EXISTING_FORWARDING_ON")
                return
            receipt = {"schema": 1, "device": DEVICE, "fingerprint": fingerprint(),
                       "original": {FORWARDING: False, GRO_LIST: False}, "script_sha256": digest}
            write(STATE, json.dumps(receipt).encode(), 0o600)
        if not SCRIPT.exists():
            if receipt["script_sha256"] != digest:
                raise ValueError("TAILNET_GRO_RECEIPT_CODE_MISMATCH")
            write(SCRIPT, script, 0o644)
        write(UNIT, UNIT_BODY, 0o644)
    run("systemctl", "daemon-reload")
    try:
        run("systemctl", "start", SERVICE, timeout=30)
        if not settings(observed(), applying=True):
            raise ValueError("TAILNET_GRO_PERSISTENCE_READBACK_MISMATCH")
        run("systemctl", "enable", SERVICE, timeout=15)
    except (OSError, ValueError, subprocess.SubprocessError):
        run("systemctl", "disable", "--now", SERVICE, check=False, timeout=30)
        restore()
        raise
    print("PROJECT_TAILSCALE_GRO=VERIFIED_AND_PERSISTENT")


def uninstall():
    if not STATE.exists() and not STATE.is_symlink():
        print("PROJECT_TAILSCALE_GRO=NO_OWNED_CHANGE")
        return
    receipt = baseline()
    verify_owned_installation(receipt)
    if UNIT.exists():
        run("systemctl", "disable", "--now", SERVICE, timeout=30)
    restore()
    with locked():
        verify_owned_installation(baseline())
        UNIT.unlink(missing_ok=True)
        SCRIPT.unlink(missing_ok=True)
        root_path(STATE, secret=True).unlink()
    run("systemctl", "daemon-reload")


if __name__ == "__main__":
    try:
        if os.geteuid() != 0 or sys.argv[1:] not in (["apply"], ["restore"]):
            raise ValueError("TAILNET_GRO_ROOT_OPERATION_REQUIRED")
        (activate if sys.argv[1] == "apply" else restore)()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        code = str(error)
        print(code if re.fullmatch(r"TAILNET_GRO_[A-Z_]+", code) else "TAILNET_GRO_OPERATION_FAILED",
              file=sys.stderr)
        raise SystemExit(1) from None
