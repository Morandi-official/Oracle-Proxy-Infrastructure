"""Check transparent routing with the production profile on a disposable Windows runner."""
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

DEVICE = "FlClashCloudTest"


def wait_for_route(process):
    command = f"""
    $selected = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue
    if (@($selected | Where-Object InterfaceAlias -eq '{DEVICE}').Count -eq 0) {{ exit 1 }}
    """
    deadline = time.monotonic() + 16
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("WINDOWS_TUN_CORE_EXITED")
        result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                                capture_output=True, timeout=8)
        if result.returncode == 0:
            try:
                with socket.create_connection(("127.0.0.1", 7890), timeout=0.5):
                    return
            except OSError:
                pass
        time.sleep(0.4)
    raise RuntimeError("WINDOWS_TUN_ROUTE_NOT_SELECTED")


def check_https(name, url, proxy_args, exits):
    result = subprocess.run(["curl.exe", "--silent", "--show-error", "--fail",
                             "--connect-timeout", "7", "--max-time", "10",
                             *proxy_args, url], capture_output=True, text=True, timeout=13)
    address = re.search(r"(?m)^ip=(\S+)$", result.stdout)
    passed = result.returncode == 0 and address is not None and address[1] in exits
    detail = "PASS" if passed else f"CURL_{result.returncode}" if result.returncode else "UNEXPECTED_EXIT"
    print(f"WINDOWS_TUN_{name}={detail}", flush=True)
    return passed


def probe_tun(binary, profile, expected_backup):
    profile["tun"]["enable"] = True
    profile["tun"]["device"] = DEVICE
    with tempfile.TemporaryDirectory(prefix="flclash-windows-tun-") as directory:
        config = Path(directory) / "profile.yaml"
        config.write_text(json.dumps(profile), encoding="utf-8")
        process = subprocess.Popen([binary, "-d", directory, "-f", str(config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_route(process)
            print("WINDOWS_TUN_ROUTE_SELECTED=PASS", flush=True)
            numeric = "https://1.1.1.1/cdn-cgi/trace"
            hostname = "https://www.cloudflare.com/cdn-cgi/trace"
            exits = {expected_backup}
            return all([
                check_https("MIXED_NUMERIC", numeric, ["--proxy", "http://127.0.0.1:7890", "--noproxy", ""], exits),
                check_https("TRANSPARENT_NUMERIC", numeric, ["--noproxy", "*"], exits),
                check_https("TRANSPARENT_DNS", hostname, ["--noproxy", "*"], exits | {"2603:c020:c015:8100::10"}),
            ])
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            # Let the operating system restore routes before the caller contacts the admin API.
            time.sleep(2)
