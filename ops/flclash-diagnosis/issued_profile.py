"""Check an issued FlClash profile using an isolated CI account."""
import hashlib
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


def main():
    admin = Admin()
    state = admin.api("/api/control")
    wanted = os.environ.get("CI_USERNAME_FINGERPRINT", "")
    if not re.fullmatch(r"[a-f0-9]{64}", wanted):
        raise RuntimeError("CI_ACCOUNT_PROOF_UNAVAILABLE")
    matches = [user for user in state["users"] if user.get("username") and
               hashlib.sha256(user["username"].encode()).hexdigest() == wanted]
    if len(matches) != 1 or matches[0].get("is_admin_account") is not False:
        raise RuntimeError("ISOLATED_CI_ACCOUNT_REQUIRED")
    ci = matches[0]
    if ci["status"] != "active":
        raise RuntimeError("CI_ACCOUNT_UNAVAILABLE")

    created = admin.api("/api/flclash/create", {"user_id": ci["id"]}, expected=201)["profile"]
    profile_id = str(uuid.UUID(created["id"]))
    path = "/api/flclash/" + profile_id
    try:
        url = admin.api(path, {"action": "link"})["url"]
        profile = download_profile(url, profile_id)
        print("PRODUCTION_FLCLASH_IMPORT=PASS", flush=True)
        profile["tun"]["enable"] = False
        exits = {node["server"] for node in profile["proxies"] if node["type"] == "wireguard"}
        if not exits:
            raise RuntimeError("ISSUED_UDP_NODES_MISSING")
        if any(ipaddress.ip_address(address).version != 4 for address in exits):
            raise RuntimeError("ISSUED_UDP_ENDPOINT_INVALID")
        if not probe(sys.argv[1], profile, exits, "2603:c020:c015:8100::10"):
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


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
            code = type(error).__name__
        print("FLCLASH_IMPORT_OBSERVATION=" + code, flush=True)
        sys.exit(1)
