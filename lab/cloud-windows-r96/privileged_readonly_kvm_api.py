"""R96 privileged READ-ONLY KVM API-version test. Does not create a VM.

KVM_GET_API_VERSION (0xAE00) reads the version of the available KVM API.
The only open is /dev/kvm. No VM_CREATE, no VCPU, no device IO, no reboot,
guest binary, ISO, network change, disk creation or kernel module change.
"""
from __future__ import annotations
import errno
import fcntl
import json
import os

KVM_GET_API_VERSION = 0xAE00
EXPECTED_API_VERSION = 12


def main() -> None:
    result = {
        "schema": "r96-privileged-kvm-readonly-api-v1",
        "github_hosted_linux": (os.environ.get("GITHUB_ACTIONS") == "true"
                 and os.environ.get("RUNNER_OS") == "Linux"
                 and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"),
        "kvm_api_version": None,
        "kvm_api_usable": False,
        "kvm_guest_created": False,
        "kvm_guest_booted": False,
        "kvm_windows_wfp_tested": False,
        "authorization_for_vm_launch": False,
    }
    if result["github_hosted_linux"] and os.path.exists("/dev/kvm"):
        try:
            fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
            try:
                version = int(fcntl.ioctl(fd, KVM_GET_API_VERSION))
                result["kvm_api_version"] = version
                result["kvm_api_usable"] = version == EXPECTED_API_VERSION
            finally:
                os.close(fd)
        except OSError as ex:
            result["kernel_access_errno"] = errno.errorcode.get(ex.errno, "OTHER")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
