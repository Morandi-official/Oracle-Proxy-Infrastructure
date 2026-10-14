"""Create throwaway WireGuard X25519 keys strictly inside CI's temp directory.

No keys are printed, committed, uploaded, reused, or transmitted. Requires
cryptography, pinned by the GitHub Actions lab workflow.
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


def main():
    destination = Path(os.environ["WG_LAB_EPHEMERAL_KEY_FILE"]).resolve()
    temp_root = Path(os.environ["RUNNER_TEMP"]).resolve()
    if destination.parent != temp_root or destination.name != "wg-lab-session.bin":
        raise RuntimeError("Lab key file must be exactly inside ephemeral runner temp")

    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    payload = (
        a.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        + b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        + b.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        + a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    if len(payload) != 128:
        raise RuntimeError("Incorrect X25519 ephemeral bundle size")
    with os.fdopen(os.open(str(destination), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as f:
        f.write(payload)
    print("LAB_KEYS_READY: exactly two new ephemeral X25519 keypairs; no key material logged")


if __name__ == "__main__":
    main()
