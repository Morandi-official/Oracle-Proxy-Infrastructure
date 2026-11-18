"""Read only the reported device and encrypt its sanitized diagnostic result."""
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time

from issued_profile import Admin, download_profile

TARGET = "f2aff98879960fdc71a25539c1eefb11398463e9a0738ad1d38a6c0925f606a0"
PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsE460nfacuupCoVgy3P9
HgcR9vpOBauTKj2anJRkQeL5E+pUjbP1TfoFvSTI12wMEygjCaG+f/xGvTFCEQhm
xx4KzEyFvjZSuGapRinpeH3nOpDtVFulJtZHoY+QXL5Ti479bwTXMYcInkNxxF8W
HvlPd7hS9zujEAojQdBNVZ2dIzeAEyFDyXTXil05NrlafpjpbmlGlLYTlfFsfCha
GpveSyRsjroyR5McdMOtHTG+DoCIDoKwsL8WukNvW/JBeZHy2lwIBlWyN8nU4nON
k9gqCkfOvvtyxbjlkvHm/2PI6KJrFPdkeFefzdks/YDg3caZStR6S3ZY7Ijo82FJ
g7itNA3k5Mhl+ethBbU31U8omZA1TwB/3uqTN5MnS4q3PGxfgHIPOmFwbpOZ/7yh
odmTO3mLhpRiUiyjcaomKxKxsh6avqbLzGF9Mz3NuT9XUjRdI7WCMZNo4bzHLMdI
t6nX4qMvrba6RMIkOaYxCDSLWyiMuAxPrXsYLEeeJfXxAgMBAAE=
-----END PUBLIC KEY-----
"""


def run():
    admin = Admin()
    state = admin.api("/api/control")
    profiles = admin.api("/api/flclash")["profiles"]
    selected = [row for row in profiles if hashlib.sha256(row["device_id"].encode()).hexdigest() == TARGET]
    if len(selected) != 1:
        raise RuntimeError("REPORTED_PROFILE_NOT_UNIQUE")
    row = selected[0]
    user = next(user for user in state["users"] if user["id"] == row["user_id"])
    peer = next((peer for peer in state["peers"]
                 if peer["user_id"] == row["user_id"] and
                 hashlib.sha256(peer["public_key"].encode()).hexdigest()[:12] == row["device_id"]), {})
    assert user["username"] == "morandi"
    policy = user.get("ingress", {})
    result = {
        "access": policy.get("access"),
        "preferred": policy.get("preferred"),
        "active": user["status"] == "active",
        "profile": row["status"],
        "present": peer.get("present"),
        "revoked": peer.get("revoked"),
        "handshake": peer.get("handshake") or row.get("last_used_at"),
        "fresh": not state.get("error") and 0 <= time.time() - state["observed_at"] <= 20,
    }
    if row["status"] == "active":
        # The link action returns the existing URL. No key or token is regenerated.
        try:
            url = admin.api("/api/flclash/" + row["id"], {"action": "link"})["url"]
            profile = download_profile(url, row["id"])
            endpoints = state.get("ingress_endpoints", {})
            keys = state.get("endpoint_public_keys", {})
            nodes = profile["proxies"]
            def node_status(role):
                node = next((node for node in nodes if node["server"] == endpoints.get(role)), None)
                return node and [
                    node["port"],
                    node["public-key"] == keys.get(role),
                    node["type"] == "wireguard",
                ]
            result["primary"] = node_status("primary")
            result["backup"] = node_status("backup")
            result["import"] = "ok"
            group = next((group for group in profile.get("proxy-groups", []) if group["type"] == "fallback"), {})
            first = next((node["server"] for node in nodes
                          if node["name"] in group.get("proxies", [])[:1]), None)
            result["order"] = next((role for role, address in endpoints.items() if address == first), None)
        except (RuntimeError, KeyError, ValueError, TypeError):
            result["import"] = "failed"
    plaintext = json.dumps(result, separators=(",", ":")).encode()
    with tempfile.NamedTemporaryFile() as key:
        key.write(PUBLIC_KEY)
        key.flush()
        encrypted = subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", key.name,
                                    "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256"],
                                   input=plaintext, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
    print("SEALED_FLCLASH_READBACK=" + base64.b64encode(encrypted).decode(), flush=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = type(error).__name__
        print("FLCLASH_READBACK_ERROR=" + code, flush=True)
        sys.exit(1)
