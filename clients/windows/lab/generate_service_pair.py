"""Write TWO never-uploaded narrow-route WireGuard configs in ephemeral CI.

Keys come from generate_lab_keys.py (two independent fresh X25519 key pairs);
nothing secret is written to stdout, GitHub environment, or the source tree.
"""
import base64
import os
from pathlib import Path


def main() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("Only ephemeral GitHub-hosted Windows runners allowed")
    session = Path(os.environ["WG_LAB_EPHEMERAL_KEY_FILE"])
    data = session.read_bytes()
    if len(data) != 128:
        raise RuntimeError("Missing two isolated test peer keypairs")
    root = Path(os.environ["ProgramData"]) / "OracleProxyLab" / "config"
    if not root.is_dir():
        raise RuntimeError("Expected protected lab directory missing")

    a_private, b_public, b_private, a_public = (
        data[0:32], data[32:64], data[64:96], data[96:128]
    )
    for label, private, other_public, local, remote, listener, endpoint in (
        ("lab-peer-a", a_private, b_public, "10.249.129.1", "10.249.129.2", 52741, 52742),
        ("lab-peer-b", b_private, a_public, "10.249.129.2", "10.249.129.1", 52742, 52741),
    ):
        ipv6_local = "fd42:14::1" if label == "lab-peer-a" else "fd42:14::2"
        ipv6_remote = "fd42:14::2" if label == "lab-peer-a" else "fd42:14::1"
        text = (
            "[Interface]\n"
            f"PrivateKey = {base64.b64encode(private).decode('ascii')}\n"
            f"Address = {local}/32, {ipv6_local}/128\n"
            f"ListenPort = {listener}\n"
            "\n[Peer]\n"
            f"PublicKey = {base64.b64encode(other_public).decode('ascii')}\n"
            f"AllowedIPs = {remote}/32, {ipv6_remote}/128\n"
            f"Endpoint = 127.0.0.1:{endpoint}\n"
            "PersistentKeepalive = 1\n"
        )
        path = root / (label + ".conf")
        with os.fdopen(os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                       "w", encoding="ascii", newline="\n") as output:
            output.write(text)
    print("LAB_CONFIG_READY: two narrow-route localhost-only WireGuard profiles created without logging secrets")


if __name__ == "__main__":
    main()
