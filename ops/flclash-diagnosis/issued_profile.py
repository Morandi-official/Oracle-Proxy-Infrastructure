"""Check an issued FlClash profile using an isolated CI account."""
import secrets
import http.cookiejar
import json
import ipaddress
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "distribution"))

from flclash_live_probe import NoRedirect, probe

BASE = "https://vpn-admin.morandi.dpdns.org"


class Admin:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.http = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(self.cookies))
        self.request("/login/")
        csrf = self.csrf()
        form = urllib.parse.urlencode({
            "username": os.environ.pop("ADMIN_LOCAL_ACCEPTANCE_USERNAME"),
            "password": os.environ.pop("ADMIN_LOCAL_ACCEPTANCE_PASSWORD"),
            "csrfmiddlewaretoken": csrf,
        }).encode()
        self.request("/login/", form, "application/x-www-form-urlencoded", expected=302)
        if not any(cookie.name == "__Host-oracle_admin" for cookie in self.cookies):
            raise RuntimeError("ADMIN_SESSION_UNAVAILABLE")

    def csrf(self):
        return next(cookie.value for cookie in self.cookies if cookie.name == "__Host-oracle_csrf")

    def request(self, path, body=None, content_type=None, expected=200):
        headers = {"Referer": BASE + "/login/"}
        if body is not None:
            headers.update({"Content-Type": content_type, "X-CSRFToken": self.csrf()})
        try:
            with self.http.open(urllib.request.Request(BASE + path, body, headers), timeout=15) as response:
                if response.status != expected:
                    raise RuntimeError("UNEXPECTED_ADMIN_RESPONSE")
                return response.read(262145)
        except urllib.error.HTTPError as error:
            if error.code != expected:
                raise RuntimeError(f"ADMIN_HTTP_{error.code}") from None
            return b""

    def api(self, path, payload=None, expected=200):
        body = None if payload is None else json.dumps(payload).encode()
        return json.loads(self.request(path, body, "application/json", expected))


def download_profile(url, profile_id):
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme, parts.netloc) != ("https", urllib.parse.urlsplit(BASE).netloc) or parts.query or parts.fragment:
        raise RuntimeError("IMPORT_URL_INVALID")
    if not re.fullmatch(rf"/api/flclash/import/{profile_id}/[A-Za-z0-9_-]{{43}}/profile.yaml", parts.path):
        raise RuntimeError("IMPORT_URL_INVALID")
    http = urllib.request.build_opener(NoRedirect())
    try:
        with http.open(url, timeout=15) as response:
            if response.headers.get_content_type() != "application/yaml":
                raise RuntimeError("IMPORT_CONTENT_TYPE_INVALID")
            return json.loads(response.read(262145))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"IMPORT_HTTP_{error.code}") from None


def probe_account(admin, account_id, expected_backup):
    created = admin.api("/api/flclash/create", {"user_id": account_id}, expected=201)["profile"]
    profile_id = str(uuid.UUID(created["id"]))
    path = "/api/flclash/" + profile_id
    try:
        url = admin.api(path, {"action": "link"})["url"]
        profile = download_profile(url, profile_id)
        print("PRODUCTION_FLCLASH_IMPORT=PASS", flush=True)
        profile["tun"]["enable"] = False
        exits = {node["server"] for node in profile["proxies"] if node["type"] == "wireguard"}
        if expected_backup not in exits:
            raise RuntimeError("ISSUED_BACKUP_NODE_MISSING")
        if any(ipaddress.ip_address(address).version != 4 for address in exits):
            raise RuntimeError("ISSUED_UDP_ENDPOINT_INVALID")
        if not probe(sys.argv[1], profile, {expected_backup}, "2603:c020:c015:8100::10"):
            raise RuntimeError("ISSUED_PROFILE_PROXY_FAILED")
        for _ in range(8):
            profiles = admin.api("/api/flclash")["profiles"]
            ci_profile = next(row for row in profiles if row["id"] == profile_id)
            if ci_profile.get("last_used_at"):
                print("ISSUED_PROFILE_SERVER_HANDSHAKE=PASS", flush=True)
                return
            time.sleep(2)
        raise RuntimeError("ISSUED_PROFILE_HANDSHAKE_NOT_OBSERVED")
    finally:
        if admin.api(path, {"action": "revoke"}).get("deleted") is not True:
            raise RuntimeError("CI_FLCLASH_PROFILE_RETIREMENT_UNCONFIRMED")
        print("CI_FLCLASH_PROFILE_RETIRED=PASS", flush=True)


def main():
    admin = Admin()
    username = "ci-flclash-" + uuid.uuid4().hex
    state = admin.api("/api/control")
    if any(user.get("username") == username or user.get("name") == username for user in state["users"]):
        raise RuntimeError("TEMPORARY_ACCOUNT_COLLISION")
    try:
        saved = admin.api("/api/control", {"operation": "account.save", "data": {
            "id": None,
            "name": username,
            "username": username,
            "password": secrets.token_urlsafe(32),
            "device_limit": 1,
            "quota_bytes": 10485760,
            "expires_at": int(time.time()) + 3600,
            "enabled": True,
            "ingress_access": "backup",
            "ingress_preferred": "backup",
        }})
        account_id = str(uuid.UUID(saved["saved_user_id"]))
        if not any(user["id"] == account_id and user.get("username") == username and
                   user.get("is_admin_account") is False and user["status"] == "active"
                   for user in saved["users"]):
            raise RuntimeError("TEMPORARY_ACCOUNT_NOT_VERIFIED")
        print("TEMPORARY_ACCOUNT_CREATED=PASS", flush=True)
        probe_account(admin, account_id, saved["ingress_endpoints"]["backup"])
    finally:
        state = admin.api("/api/control")
        owned = [user for user in state["users"] if user.get("name") == username]
        if owned:
            if len(owned) != 1 or owned[0].get("username") not in (None, username) or owned[0].get("is_admin_account") is not False:
                raise RuntimeError("TEMPORARY_ACCOUNT_RETIREMENT_SCOPE_MISMATCH")
            account_id = str(uuid.UUID(owned[0]["id"]))
            state = admin.api("/api/control", {"operation": "account.delete", "data": {"user_id": account_id}})
            if any(user["id"] == account_id and user.get("username") for user in state["users"]):
                raise RuntimeError("TEMPORARY_ACCOUNT_RETIREMENT_UNCONFIRMED")
            print("TEMPORARY_ACCOUNT_RETIRED=PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = type(error).__name__
        print("FLCLASH_IMPORT_OBSERVATION=" + code, flush=True)
        sys.exit(1)
