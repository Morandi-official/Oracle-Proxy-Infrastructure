"""Opt-in Oracle Headscale control plane and dedicated Tailscale exit."""

import importlib.util
import ipaddress
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
ORIGIN = "https://vpn-admin.morandi.dpdns.org"
HOST = "vpn-admin.morandi.dpdns.org"
CONFIG = Path("/etc/oracle-proxy-tailnet")
BINARIES = Path("/usr/local/libexec/oracle-proxy-tailnet")
HEADSCALE_CONFIG = CONFIG / "headscale.yaml"
PROFILE = Path("/etc/oracle-proxy-control/tailscale.json")
OWNER = CONFIG / "owner"
OWNER_CONTENT = b"oracle-proxy-tailnet-v1\n"
HEADSCALE_USER = "oracle-proxy-headscale"
HEADSCALE_STATE = Path("/var/lib/oracle-proxy-tailnet-headscale")
EXIT_STATE = Path("/var/lib/oracle-proxy-tailnet-exit")
EXIT_SOCKET = "/run/oracle-proxy-tailnet-exit/tailscaled.sock"
CONTROL_SERVICE = "oracle-proxy-control.service"
DROP_IN = Path("/etc/systemd/system/oracle-proxy-control.service.d/oracle-proxy-tailnet.conf")
HEADSCALE_SERVICE = "oracle-proxy-headscale.service"
GUARD_SERVICE = "oracle-proxy-tailnet-guard.service"
EXIT_SERVICE = "oracle-proxy-tailnet-exit.service"
UNITS = (HEADSCALE_SERVICE, GUARD_SERVICE, EXIT_SERVICE)
NFT = "/usr/sbin/nft"
TABLE = "oracle_proxy_tailscale"
EXITS = {"0.0.0.0/0", "::/0"}
TAG = "tag:oracle-exit"
CADDY_BLOCK = b"""    # BEGIN Oracle Proxy Tailscale coordinator
    @oracle_proxy_headscale path /key /ts2021 /machine/ping-response
    handle @oracle_proxy_headscale {
        reverse_proxy 127.0.0.1:8789
    }
    # END Oracle Proxy Tailscale coordinator
"""


def command(*arguments, timeout=15, check=True, input=None):
    return subprocess.run(arguments, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=check)


def safe_target(path):
    if path.is_symlink() or (path.exists() and
                             (path.stat().st_uid != 0 or path.stat().st_mode & 0o022)):
        raise ValueError("UNTRUSTED_TAILNET_FILESYSTEM")
    return path


def atomic(path, value, mode=0o644):
    safe_target(path)
    safe_target(path.parent)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tailnet-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(value)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def owned():
    safe_target(CONFIG)
    return safe_target(OWNER).is_file() and OWNER.read_bytes() == OWNER_CONTENT


def render_caddy(source, enabled):
    if source.count(CADDY_BLOCK) > 1 or not source.startswith(HOST.encode() + b" {"):
        raise ValueError("TAILNET_CADDY_LAYOUT_UNRECOGNIZED")
    source = source.replace(CADDY_BLOCK, b"")
    if b"@oracle_proxy_headscale" in source:
        raise ValueError("TAILNET_CADDY_LAYOUT_UNRECOGNIZED")
    if not enabled:
        return source
    catchall = b"\n    handle {\n"
    if source.count(catchall) != 1:
        raise ValueError("TAILNET_CADDY_LAYOUT_UNRECOGNIZED")
    return source.replace(catchall, b"\n" + CADDY_BLOCK.rstrip(b"\n") + catchall, 1)


def enabled():
    return owned() and safe_target(PROFILE).is_file()


def set_frontend(main, snippet, enabled):
    current = safe_target(snippet).read_bytes()
    replacement = render_caddy(current, enabled)
    if current == replacement:
        return
    atomic(snippet, replacement)
    try:
        command("caddy", "validate", "--config", safe_target(main), "--adapter", "caddyfile", timeout=25)
        command("systemctl", "reload", "caddy.service", timeout=25)
    except (OSError, subprocess.SubprocessError):
        atomic(snippet, current)
        command("systemctl", "reload", "caddy.service", timeout=25, check=False)
        raise


def curl(url, *options):
    return command("curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
                   "--proto", "=https", "--connect-timeout", "4", "--max-time", "8",
                   "--max-filesize", "32768", *options, url, timeout=10).stdout


def local_https(path):
    return curl(ORIGIN + path, "--resolve", f"{HOST}:443:127.0.0.1")


def verify_key():
    value = json.loads(local_https("/key?v=120"))
    if not isinstance(value.get("publicKey"), str) or not re.fullmatch(r"mkey:[a-f0-9]{64}", value["publicKey"]):
        raise ValueError("TAILNET_CADDY_CONTROL_ENDPOINT_UNAVAILABLE")


def public_egress():
    endpoints = json.loads((REPO / "ops/network/endpoints.json").read_bytes())
    ipv4 = ipaddress.IPv4Address(endpoints["primary"]["public_ipv4"])
    if endpoints["api_host"] != HOST or endpoints["active"] != "primary" or not ipv4.is_global:
        raise ValueError("TAILNET_ACTIVE_PRIMARY_UNRECOGNIZED")
    traces = (
        curl("https://1.1.1.1/cdn-cgi/trace", "-4"),
        curl("https://[2606:4700:4700::1111]/cdn-cgi/trace", "-6"),
    )
    addresses = []
    for byte_trace, parse in zip(traces, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        values = [line[3:] for line in byte_trace.decode("ascii").splitlines() if line.startswith("ip=")]
        if len(values) != 1 or not (address := parse(values[0])).is_global:
            raise ValueError("TAILNET_PUBLIC_EGRESS_UNAVAILABLE")
        addresses.append(address)
    if addresses[0] != ipv4:
        raise ValueError("TAILNET_PRIMARY_EGRESS_MISMATCH")
    return tuple(map(str, addresses))


def table_exists():
    tables = json.loads(command(NFT, "--json", "list", "tables").stdout)["nftables"]
    return any(item.get("table", {}).get("family") == "inet"
               and item["table"]["name"] == TABLE for item in tables)


def headscale(*args):
    return json.loads(command(BINARIES / "headscale", "--config", HEADSCALE_CONFIG, *args,
                              "--output", "json").stdout)


def tailscale(*args, **kwargs):
    return command(BINARIES / "tailscale", "--socket=" + EXIT_SOCKET, *args, **kwargs)


def wait_for(observe, deadline=30):
    expires = time.monotonic() + deadline
    while time.monotonic() < expires:
        try:
            if value := observe():
                return value
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(0.25)
    raise ValueError("TAILNET_STAGE_READINESS_TIMEOUT")


def running_exit():
    status = json.loads(tailscale("status", "--json", check=False).stdout)
    identifier = (status.get("Self") or {}).get("ID")
    if status.get("BackendState") == "Running" and isinstance(identifier, str) and identifier.isdecimal():
        number = int(identifier)
        if 0 < number < 2**63:
            return number
    return None


def route_approved(identifier):
    nodes = headscale("nodes", "list-routes", "--identifier", str(identifier))
    if not isinstance(nodes, list) or len(nodes) != 1:
        return False
    node = nodes[0]
    return (node.get("id") == identifier and TAG in node.get("tags", [])
            and EXITS <= set(node.get("approved_routes", []))
            and EXITS <= set(node.get("available_routes", [])))


def controller_ready():
    return json.loads(local_https("/api/tailscale/v1/ready")) == {"ready": True}


def coordinator_ready():
    headscale("users", "list")
    return True


def preflight(main, snippet):
    if os.geteuid() != 0:
        raise ValueError("TAILNET_ROOT_REQUIRED")
    if not Path("/dev/net/tun").is_char_device() or not Path(NFT).is_file():
        raise ValueError("TAILNET_TUN_OR_NFT_UNAVAILABLE")
    for path in (Path("/proc/sys/net/ipv4/ip_forward"), Path("/proc/sys/net/ipv6/conf/all/forwarding")):
        if path.read_text().strip() != "1":
            raise ValueError("TAILNET_EXISTING_FORWARDING_REQUIRED")
    safe_target(main)
    render_caddy(safe_target(snippet).read_bytes(), True)
    if command("systemctl", "is-active", "--quiet", "tailscaled.service", check=False).returncode == 0:
        raise ValueError("TAILNET_FOREIGN_DAEMON")
    command("systemctl", "is-active", "--quiet", CONTROL_SERVICE)
    if b"tailscale.ready" not in safe_target(Path("/usr/local/libexec/oracle-project/control-agent.py")).read_bytes():
        raise ValueError("TAILNET_ACCOUNT_CONTROLLER_DEPLOYMENT_REQUIRED")
    local_https("/login/")
    if not owned():
        occupied = (CONFIG, BINARIES, OWNER, HEADSCALE_STATE, EXIT_STATE, PROFILE, DROP_IN,
                    *(Path("/etc/systemd/system") / unit for unit in UNITS))
        if any(path.exists() or path.is_symlink() for path in occupied) or table_exists():
            raise ValueError("TAILNET_FOREIGN_DEPLOYMENT")
        if command("ip", "link", "show", "dev", "tailscale0", check=False).returncode == 0:
            raise ValueError("TAILNET_FOREIGN_INTERFACE")


def ensure_runtime():
    if not owned():
        CONFIG.mkdir(mode=0o755)
        atomic(OWNER, OWNER_CONTENT, 0o600)
    # The GitOps bridge runs with umask 0077. Headscale runs under a separate
    # uid and needs to traverse these root-owned directories.
    safe_target(CONFIG).chmod(0o755)
    BINARIES.mkdir(mode=0o755, exist_ok=True)
    safe_target(BINARIES).chmod(0o755)
    with tempfile.TemporaryDirectory(prefix="oracle-tailnet-assets-") as temporary:
        directory = Path(temporary)
        command(sys.executable, "-I", SOURCE / "fetch_tools.py", directory, timeout=240)
        for name in ("headscale", "tailscale", "tailscaled"):
            atomic(BINARIES / name, (directory / name).read_bytes(), 0o755)


def verify_service_identity(account, policy):
    # Exercise the actual service identity without initializing its state or
    # logging service output. The systemd unit owns database/key creation.
    checks = (
        (BINARIES / "headscale", "version"),
        ("/usr/bin/test", "-r", HEADSCALE_CONFIG),
        ("/usr/bin/test", "-r", policy),
    )
    try:
        for arguments in checks:
            subprocess.run(arguments, user=account.pw_uid, group=account.pw_gid, extra_groups=(),
                           timeout=8, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("TAILNET_COORDINATOR_SERVICE_IDENTITY_ACCESS") from None


def install_configuration():
    try:
        account = pwd.getpwnam(HEADSCALE_USER)
    except KeyError:
        command("useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                HEADSCALE_STATE, "--shell", "/usr/sbin/nologin", HEADSCALE_USER)
        account = pwd.getpwnam(HEADSCALE_USER)
    if (not 0 < account.pw_uid < 1000 or account.pw_dir != str(HEADSCALE_STATE)
            or account.pw_shell != "/usr/sbin/nologin"):
        raise ValueError("TAILNET_FOREIGN_SERVICE_ACCOUNT")
    state = HEADSCALE_STATE
    policy = CONFIG / "policy.json"
    configuration = {
        "server_url": ORIGIN,
        "listen_addr": "127.0.0.1:8789",
        "metrics_listen_addr": "",
        "grpc_listen_addr": "127.0.0.1:50489",
        "unix_socket": "/run/oracle-proxy-tailnet-headscale/headscale.sock",
        "unix_socket_permission": "0660",
        "disable_check_updates": True,
        "noise": {"private_key_path": str(state / "noise.key")},
        "prefixes": {"v4": "100.100.46.0/24", "v6": "fd7a:115c:a1e0:46::/64"},
        "database": {"type": "sqlite", "sqlite": {"path": str(state / "db.sqlite")}},
        "policy": {"mode": "file", "path": str(policy)},
        "derp": {"server": {"enabled": False}, "urls": ["https://controlplane.tailscale.com/derpmap/default"],
                 "paths": [], "auto_update_enabled": True, "update_frequency": "24h"},
        "dns": {"magic_dns": False, "override_local_dns": True,
                "nameservers": {"global": ["1.1.1.1", "2606:4700:4700::1111"], "split": {}}},
    }
    atomic(HEADSCALE_CONFIG, json.dumps(configuration).encode())
    atomic(policy, json.dumps({
        "tagOwners": {TAG: []},
        "autoApprovers": {"exitNode": [TAG]},
        "grants": [{"src": ["autogroup:member"], "dst": ["autogroup:internet"], "ip": ["*"]}],
    }).encode())
    verify_service_identity(account, policy)
    hosts = Path("/etc/hosts").read_text()
    if any(HOST in line.split("#", 1)[0].split() for line in hosts.splitlines()):
        raise ValueError("TAILNET_EXIT_EXISTING_HOST_OVERRIDE")
    atomic(CONFIG / "exit-hosts", (hosts.rstrip("\n") + f"\n127.0.0.1 {HOST}\n").encode())
    spec = importlib.util.spec_from_file_location(
        "oracle_tailnet_policy", REPO / "server/admin-oracle/control/tailscale_egress.py")
    policy_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy_module)
    if policy_module.TABLE != TABLE or policy_module.INTERFACE != "tailscale0":
        raise ValueError("TAILNET_GUARD_CONFIGURATION_MISMATCH")
    # Reinstall this specific owned guard atomically on boot before the exit starts.
    # add is idempotent in nftables, and delete removes any expired pre-reboot leases.
    rules = f"add table inet {TABLE}\ndelete table inet {TABLE}\n" + policy_module.install_rules()
    atomic(CONFIG / "guard.nft", rules.encode(), 0o600)
    command(NFT, "--check", "-f", CONFIG / "guard.nft")
    for unit in UNITS:
        atomic(Path("/etc/systemd/system") / unit, (SOURCE / unit).read_bytes())
    command("systemctl", "daemon-reload")


def register_exit():
    command("systemctl", "start", EXIT_SERVICE, timeout=35)
    wait_for(lambda: Path(EXIT_SOCKET).is_socket())
    if identifier := running_exit():
        return identifier
    key = headscale("preauthkeys", "create", "--tags", TAG, "--expiration", "5m").get("key")
    if not isinstance(key, str) or not re.fullmatch(r"hskey-auth-[A-Za-z0-9_-]{20,200}", key):
        raise ValueError("TAILNET_EXIT_KEY_UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="oracle-tailnet-key-", dir="/run") as temporary:
        secret = Path(temporary) / "key"
        atomic(secret, key.encode(), 0o600)
        # Keep the engine's advertised routes usable. The dedicated nft guard
        # rejects local services and forwards only current account leases.
        tailscale("up", "--login-server=" + ORIGIN, "--auth-key=file:" + str(secret),
                  "--hostname=oracle-proxy-exit", "--advertise-exit-node", "--accept-dns=false",
                  "--accept-routes=false", "--shields-up=false", "--timeout=40s", timeout=45)
    return wait_for(running_exit)


def rollback(main, snippet):
    if not owned():
        if safe_target(PROFILE).exists():
            raise ValueError("TAILNET_FOREIGN_DEPLOYMENT")
        print("PROJECT_TAILSCALE_STAGE=INACTIVE")
        return
    # Stop the dedicated forwarding interface before removing its admission table.
    if safe_target(Path("/etc/systemd/system") / EXIT_SERVICE).is_file():
        command("systemctl", "stop", EXIT_SERVICE, timeout=30)
    if command("ip", "link", "show", "dev", "tailscale0", check=False).returncode == 0:
        raise ValueError("TAILNET_EXIT_INTERFACE_STILL_ACTIVE")
    active = safe_target(PROFILE).is_file()
    has_drop_in = safe_target(DROP_IN).is_file()
    PROFILE.unlink(missing_ok=True)
    DROP_IN.unlink(missing_ok=True)
    if active or has_drop_in:
        command("systemctl", "daemon-reload")
    if active:
        command("systemctl", "restart", CONTROL_SERVICE, timeout=50)
    set_frontend(main, snippet, False)
    installed = [unit for unit in (EXIT_SERVICE, HEADSCALE_SERVICE)
                 if safe_target(Path("/etc/systemd/system") / unit).is_file()]
    if installed:
        command("systemctl", "disable", "--now", *installed, timeout=35)
    if safe_target(Path("/etc/systemd/system") / GUARD_SERVICE).is_file():
        command("systemctl", "stop", GUARD_SERVICE)
    if table_exists():
        command(NFT, "delete", "table", "inet", TABLE)
    print("PROJECT_TAILSCALE_STAGE=INACTIVE")


def apply(main, snippet):
    print("PROJECT_TAILSCALE_STAGE=CHECKING_HOST", flush=True)
    preflight(main, snippet)
    if enabled():
        verify_key()
        identifier = running_exit()
        if identifier and route_approved(identifier) and controller_ready():
            print("PROJECT_TAILSCALE_STAGE=READY", flush=True)
            return
        raise ValueError("TAILNET_EXISTING_STAGE_UNHEALTHY")
    print("PROJECT_TAILSCALE_STAGE=CHECKING_DUAL_STACK_EGRESS", flush=True)
    ipv4, ipv6 = public_egress()
    try:
        print("PROJECT_TAILSCALE_STAGE=INSTALLING_PINNED_RUNTIME", flush=True)
        ensure_runtime()
        install_configuration()
        print("PROJECT_TAILSCALE_STAGE=STARTING_COORDINATOR", flush=True)
        command("systemctl", "start", HEADSCALE_SERVICE, timeout=30)
        try:
            wait_for(coordinator_ready)
        except ValueError:
            status = command("systemctl", "show", HEADSCALE_SERVICE, "--property=ExecMainStatus",
                             "--value", check=False).stdout.strip()
            if re.fullmatch(rb"[0-9]{1,3}", status):
                print("PROJECT_TAILSCALE_COORDINATOR_EXEC_STATUS=" + status.decode("ascii"), flush=True)
            raise
        set_frontend(main, snippet, True)
        verify_key()
        print("PROJECT_TAILSCALE_STAGE=ENROLLING_EXIT", flush=True)
        identifier = register_exit()
        wait_for(lambda: route_approved(identifier))
        print("PROJECT_TAILSCALE_STAGE=ENABLING_ACCOUNT_CONTROL", flush=True)
        safe_target(PROFILE.parent).mkdir(mode=0o755, exist_ok=True)
        safe_target(DROP_IN.parent).mkdir(mode=0o755, exist_ok=True)
        atomic(DROP_IN, b"[Unit]\nAfter=oracle-proxy-tailnet-exit.service\n\n"
                        b"[Service]\nSupplementaryGroups=oracle-proxy-headscale\n")
        atomic(PROFILE, json.dumps({"coordinator": ORIGIN, "exit_node_id": identifier,
                                   "ipv4": ipv4, "ipv6": ipv6}).encode(), 0o600)
        command("systemctl", "daemon-reload")
        command("systemctl", "restart", CONTROL_SERVICE, timeout=55)
        wait_for(controller_ready)
        command("systemctl", "enable", HEADSCALE_SERVICE, EXIT_SERVICE, timeout=20)
        print("PROJECT_TAILSCALE_STAGE=READY", flush=True)
    except Exception:
        if owned():
            try:
                rollback(main, snippet)
            except Exception:
                print("PROJECT_TAILSCALE_STAGE=ROLLBACK_INCOMPLETE", flush=True)
        raise
