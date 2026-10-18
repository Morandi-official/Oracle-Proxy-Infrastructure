"""R113 disposable local-only WireGuard profile, never committed or uploaded.

The profile cannot reroute all Internet traffic: AllowedIPs is one private /32
and its peer endpoint is localhost. The CI runner is destroyed after test.
"""
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)


def main() -> None:
    if (os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.environ.get("RUNNER_OS") != "Windows"
        or os.environ.get("GITHUB_HEAD_REF")
            != "test/r113-embedded-service-live-disposable-ci-20261018"
        or os.environ.get("ORACLE_R113_EXPLICIT_CI") != "CI_ONLY"):
        raise RuntimeError("Not the exact disposable Windows CI trial")

    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    target = temp / "OracleProxyAlphaTest.conf"
    if target.exists() or target.is_symlink():
        raise RuntimeError("Refuse preexisting native tunnel fixture")
    private = X25519PrivateKey.generate()
    remote = X25519PrivateKey.generate()
    secret = base64.b64encode(private.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode("ascii")
    public = base64.b64encode(remote.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    config = (
        "[Interface]\n"
        f"PrivateKey = {secret}\n"
        "Address = 10.249.141.1/32\n"
        "ListenPort = 59741\n\n"
        "[Peer]\n"
        f"PublicKey = {public}\n"
        "AllowedIPs = 10.249.141.2/32\n"
        "Endpoint = 127.0.0.1:59742\n"
        "PersistentKeepalive = 1\n"
    )
    # File exists exclusively in the hosted runner's isolated temp folder.
    with os.fdopen(os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                   "w", encoding="ascii", newline="\n") as f:
        f.write(config)
    print("R113_LOCALHOST_ONLY_EPHEMERAL_CONFIG_CREATED_NO_SECRETS_LOGGED")


if __name__ == "__main__":
    main()
