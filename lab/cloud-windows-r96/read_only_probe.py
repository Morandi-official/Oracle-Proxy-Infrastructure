"""R96 zero-mutation hosted CI preflight for a hypothetical real Windows guest.

No QEMU/VM is launched; does not install packages, download a Windows image,
make a snapshot, modify networking, or execute native driver/WFP operations.
KVM existence is only a capability hint, not supported nested-VM evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import pathlib
import platform

GIB = 1024 ** 3
# dockur/windows documents >=32GB free disk and >=2GB RAM to install.
# Budget extra host headroom; the preflight deliberately requires >=6GiB
# available RAM to avoid mistaking the bare minimum for practical usability.
MIN_GUEST_DISK_FREE = 32 * GIB
MIN_RUNNER_AVAILABLE_RAM = 6 * GIB
MIN_RUNNER_CPUS = 2


@dataclass(frozen=True)
class RunnerFacts:
    hosted_linux: bool
    kvm_device_exists: bool
    kvm_device_rw: bool
    hardware_virt_flag: bool
    free_workspace_disk_bytes: int
    available_memory_bytes: int
    cpu_count: int


def classify(f: RunnerFacts) -> tuple[str, ...]:
    if not f.hosted_linux:
        return ("R96_REFUSED_NOT_GITHUB_HOSTED_LINUX",)
    reasons = []
    if not (f.kvm_device_exists and f.kvm_device_rw and f.hardware_virt_flag):
        reasons.append("KVM_ACCESS_OR_NESTED_VIRT_NOT_VERIFIED")
    if f.free_workspace_disk_bytes < MIN_GUEST_DISK_FREE:
        reasons.append("WINDOWS_VM_DISK_HEADROOM_BELOW_32GIB")
    if f.available_memory_bytes < MIN_RUNNER_AVAILABLE_RAM:
        reasons.append("WINDOWS_VM_AVAILABLE_RAM_BELOW_6GIB")
    if f.cpu_count < MIN_RUNNER_CPUS:
        reasons.append("WINDOWS_VM_CPU_BELOW_2")
    if reasons:
        return tuple(reasons)
    # Not an authorization or compatibility proof: disk/CPU/KVM may be
    # sufficient yet QEMU boot, nested virtualization, licensing, secure
    # independent snapshots, guest Windows drivers and pre-login WFP fail.
    return ("R96_CAPACITY_PREFLIGHT_ONLY_NO_GUEST_OR_SECURITY_APPROVAL",)


def _read_memavailable() -> int:
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def _has_virt_flags() -> bool:
    content = pathlib.Path("/proc/cpuinfo").read_text(errors="replace")
    return any(part in content.split() for part in ("vmx", "svm"))


def read_current_runner() -> RunnerFacts:
    # Both checks are required. Never assume a random Linux machine may be
    # used for CI host inspection or later privileged native operations.
    hosted = (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and platform.system() == "Linux"
    )
    if not hosted:
        return RunnerFacts(False, False, False, False, 0, 0, 0)
    kvm = pathlib.Path("/dev/kvm")
    fs = os.statvfs(os.getcwd())
    return RunnerFacts(
        hosted_linux=True,
        kvm_device_exists=kvm.exists(),
        kvm_device_rw=os.access(kvm, os.R_OK | os.W_OK),
        hardware_virt_flag=_has_virt_flags(),
        free_workspace_disk_bytes=fs.f_bavail * fs.f_frsize,
        available_memory_bytes=_read_memavailable(),
        cpu_count=os.cpu_count() or 0,
    )


def main() -> None:
    facts = read_current_runner()
    result = {
        "schema": "r96-hosted-windows-guest-readonly-v1",
        "status": "CAPABILITY_PREFLIGHT_NOT_VIRTUAL_MACHINE_TEST",
        "reason_codes": classify(facts),
        "kvm_device_exists": facts.kvm_device_exists,
        "kvm_device_rw": facts.kvm_device_rw,
        "hardware_virt_flag_present": facts.hardware_virt_flag,
        "free_disk_gib": facts.free_workspace_disk_bytes // GIB,
        "available_memory_gib": facts.available_memory_bytes // GIB,
        "cpu_count": facts.cpu_count,
        "minimum_guest_disk_gib": MIN_GUEST_DISK_FREE // GIB,
        "nested_virtualization_officially_supported": False,
        "windows_guest_installed": False,
        "windows_guest_booted": False,
        "wfp_or_vpn_test_performed": False,
        "separate_windows_license_verified": False,
        "public_cross_host_connection_tested": False,
        "authorizes_windows_vm_launch": False,
        "authorizes_field_oracle_changes": False,
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
