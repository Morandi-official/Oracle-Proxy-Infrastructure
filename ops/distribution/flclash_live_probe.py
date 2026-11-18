"""Compare numeric HTTPS and domain HTTPS through a CI-owned WireGuard peer."""
import ast
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

BASE = "https://vpn-admin.morandi.dpdns.org/api/client/"
ROOT = Path(__file__).resolve().parents[2]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect())


def api(name, body=None, token=None):
    headers = {"X-Oracle-Client-Capabilities": "dual-stack-v1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(BASE + name,
        None if body is None else json.dumps(body).encode(), headers)
    try:
        with opener.open(req, timeout=12) as response:
            return json.loads(response.read(65537))
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"CLIENT_API_{name}_{error.code}") from None


def render(state, private, public):
    tunnel = state["tunnel"]
    addresses = [tunnel["transport_address"]]
    if tunnel.get("backup_address"):
        addresses.append(tunnel["backup_address"])
    keys = tunnel["server_public_keys"]
    if set(addresses) != set(keys):
        raise RuntimeError("INCONSISTENT_CI_INGRESS")
    tree = ast.parse((ROOT / "server/admin-oracle/console/flclash.py").read_text())
    renderer = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "configuration")
    env = dict(ipaddress=ipaddress)
    env["transport_address"] = lambda: addresses[0]
    env["ipv6_info"] = lambda: {"prefix": "fd42:6f70:78:77::/64"}
    policy = state["account"]["ingress"]
    snapshot = {"server_public_key": keys[addresses[0]]}
    if len(addresses) == 2:
        roles = [policy["preferred"], "primary" if policy["preferred"] == "backup" else "backup"]
        catalog = {role: {"public_ipv4": address} for role, address in zip(roles, addresses)}
        env["endpoint_config"] = type("Catalog", (), {"read": staticmethod(lambda: catalog)})
        snapshot["users"] = [{"id": "CI", "ingress": policy}]
        snapshot["endpoint_public_keys"] = {role: keys[address] for role, address in zip(roles, addresses)}
    else:
        env["endpoint_config"] = type("Catalog", (), {"read": staticmethod(lambda: None)})
    exec(compile(ast.Module(body=[renderer], type_ignores=[]), "<FlClash renderer>", "exec"), env)
    profile = env["configuration"](type("CI", (), {"account_id": "CI"})(),
        snapshot, {"public_key": public, "allowed_ips": tunnel["addresses"]}, private)
    profile["tun"]["enable"] = False
    return profile


def probe(binary, profile, exits, ipv6):
    with tempfile.TemporaryDirectory(prefix="flclash-ci-") as work:
        path = Path(work) / "profile.yaml"
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump(profile, file)
        with subprocess.Popen([binary, "-d", work, "-f", str(path)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as mihomo:
            results = {}
            try:
                deadline = time.monotonic() + 8
                while True:
                    if mihomo.poll() is not None:
                        raise RuntimeError("MIHOMO_EXITED")
                    try:
                        with socket.create_connection(("127.0.0.1", 7890), timeout=0.25):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("MIHOMO_LISTENER_TIMEOUT") from None
                        time.sleep(0.15)
                for name, url in (("NUMERIC", "https://1.1.1.1/cdn-cgi/trace"),
                                  ("DNS", "https://www.cloudflare.com/cdn-cgi/trace")):
                    outcome = "NO_RESPONSE"
                    for _ in range(2):
                        if mihomo.poll() is not None:
                            raise RuntimeError("MIHOMO_EXITED")
                        result = subprocess.run(
                            ["curl", "--silent", "--show-error", "--fail", "--connect-timeout", "5",
                             "--max-time", "12", "--proxy", "http://127.0.0.1:7890",
                             "--noproxy", "", url], capture_output=True, text=True, timeout=14)
                        exit_ip = re.search(r"(?m)^ip=(\S+)$", result.stdout)
                        if result.returncode == 0 and exit_ip and (exit_ip[1] in exits or name == "DNS" and exit_ip[1] == ipv6):
                            results[name] = True
                            break
                        outcome = f"CURL_{result.returncode}" if result.returncode else "UNEXPECTED_EXIT"
                        time.sleep(0.5)
                    if not results.get(name):
                        print(f"MIHOMO_CLOUD_{name}_DETAIL={outcome}", flush=True)
                    print(f"MIHOMO_CLOUD_{name}=" + ("PASS" if results.get(name) else "FAIL"), flush=True)
                return all(results.get(name) for name in ("NUMERIC", "DNS"))
            finally:
                mihomo.terminate()
                try:
                    mihomo.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    mihomo.kill()
                    mihomo.wait()


def main():
    if (os.environ.get("GITHUB_ACTIONS"), os.environ.get("RUNNER_ENVIRONMENT"),
        os.environ.get("GITHUB_REF")) != ("true", "github-hosted", "refs/heads/main"):
        raise RuntimeError("MAIN_DISPOSABLE_CLOUD_REQUIRED")
    user = os.environ.pop("ORACLE_CLIENT_ACCEPTANCE_USERNAME")
    password = os.environ.pop("ORACLE_CLIENT_ACCEPTANCE_PASSWORD")
    private = subprocess.check_output(["wg", "genkey"], text=True).strip()
    public = subprocess.check_output(["wg", "pubkey"], input=private + "\n", text=True).strip()
    fingerprint = hashlib.sha256(public.encode()).hexdigest()[:12]
    name = "CI FlClash UDP " + fingerprint
    token = api("authenticate", {"username": user, "password": password, "public_key": public,
                                 "device_name": name, "client_version": "0.3.0-rc43-ci"})["token"]
    enrolled = False
    try:
        state = api("enroll", {"device_name": name, "confirm": True}, token)
        enrolled = True
        if state["registration"]["device_id"] != fingerprint:
            raise RuntimeError("CI_DEVICE_NOT_OWNED")
        profile = render(state, private, public)
        exits = state["tunnel"]["egress_ipv4_candidates"]
        successful = probe(str(Path(sys.argv[1]).resolve()), profile, exits, state["tunnel"].get("ipv6_egress"))
        observed = api("state", token=token)["device"]["handshake_at"]
        print("MIHOMO_CLOUD_SERVER_HANDSHAKE=" + ("SEEN" if observed else "NOT_SEEN"), flush=True)
        return 0 if successful else 1
    finally:
        if enrolled:
            retired = api("device-delete", {"device_id": fingerprint}, token)
            if retired.get("current") is not True or retired.get("removed") != fingerprint:
                raise RuntimeError("CI_DEVICE_RETIREMENT_UNCONFIRMED")
            print("MIHOMO_CLOUD_TEST_IDENTITY_RETIRED=PASS", flush=True)
        else:
            snapshot = api("state", token=token)
            if snapshot.get("registration", {}).get("status") == "registered":
                api("device-delete", {"device_id": fingerprint}, token)
            else:
                api("logout", {}, token)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        code = str(error)
        if not isinstance(error, RuntimeError) or not re.fullmatch(r"[A-Za-z0-9_]{1,80}", code):
            code = type(error).__name__
        print("MIHOMO_CLOUD_ERROR=" + code, flush=True)
        sys.exit(2)
