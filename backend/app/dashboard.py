"""Browser-friendly, read-only dashboard for localhost / SSH-tunnel use only.

No cookies, external assets, or scripts. Authentication uses a Basic password equal
to ORACLE_PROXY_API_TOKEN; never send this across unencrypted public HTTP.
"""

import base64
import binascii
from datetime import datetime, timezone
from html import escape
import hmac
import os

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import HTMLResponse

from .main import wireguard_overview

router = APIRouter()

_STYLES = """
:root{color-scheme:dark;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}
body{margin:0;background:#0d111b;color:#edf1fa}
main{max-width:1080px;margin:42px auto;padding:0 24px}
h1{font-size:clamp(24px,4vw,37px);margin:6px 0 10px}
p{color:#a4b0c9}
.topline{color:#82baff;font-size:13px;letter-spacing:0.08em;font-weight:700}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:14px;margin:28px 0}
.card,.panel{border:1px solid #29364b;background:#161e2c;border-radius:14px;padding:18px}
.card .label{color:#a4b0c9;font-size:12px;margin-bottom:9px}
.card .value{font-size:24px;font-weight:700;overflow-wrap:anywhere}
.panel{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:640px}
td,th{border-bottom:1px solid #29364b;text-align:left;padding:13px 11px;font-size:13px}
th{color:#a4b0c9;font-weight:600}
tbody tr:last-child td{border-bottom:0}
.note{font-size:12px;margin-top:18px}
code{color:#a3d6ff}
"""


def _require_basic(authorization: str | None) -> None:
    expected = os.environ.get("ORACLE_PROXY_API_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="Dashboard is not configured")
    scheme, sep, value = (authorization or "").partition(" ")
    user, password = "", ""
    if sep and scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
            user, sep2, password = decoded.partition(":")
            if not sep2:
                password = ""
        except (ValueError, UnicodeError, binascii.Error):
            pass
    if not (hmac.compare_digest(user, "admin") and hmac.compare_digest(password, expected)):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="Oracle Proxy (local only)"'},
        )


def _fmt_bytes(value: object) -> str:
    try:
        amount = int(value)
        if amount < 0:
            return "—"
    except (ValueError, TypeError, OverflowError):
        return "—"
    unit = "B"
    for next_unit in ("KiB", "MiB", "GiB", "TiB"):
        if amount < 1024:
            break
        amount /= 1024
        unit = next_unit
    return f"{amount:,.1f} {unit}" if unit != "B" else f"{int(amount):,} B"


def _fmt_handshake(value: object) -> str:
    try:
        timestamp = int(value)
        if timestamp <= 0:
            return "Never"
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OverflowError, OSError):
        return "Unknown"


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(authorization: str | None = Header(default=None)) -> HTMLResponse:
    _require_basic(authorization)
    data = wireguard_overview()
    rows = []
    for peer in data["peers"]:
        address_list = peer.get("allowed_ips", [])
        addresses = ", ".join(str(x) for x in address_list) if isinstance(address_list, list) else "—"
        fields = (
            peer.get("id", "—"),
            addresses,
            _fmt_handshake(peer.get("latest_handshake", 0)),
            _fmt_bytes(peer.get("rx_bytes", 0)),
            _fmt_bytes(peer.get("tx_bytes", 0)),
        )
        rows.append("<tr>" + "".join(f"<td>{escape(str(field))}</td>" for field in fields) + "</tr>")

    body = "\n".join(rows) if rows else '<tr><td colspan="5">No peers in this snapshot</td></tr>'
    interface = escape(str(data.get("interface", "—")))
    port = escape(str(data.get("listen_port", "—")))
    collected = escape(str(data.get("collected_at", "—")))
    response = HTMLResponse(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Oracle Proxy · Read-only dashboard</title>
<style>{_STYLES}</style></head>
<body><main><div class="topline">ORACLE PROXY / INFRASTRUCTURE</div>
<h1>WireGuard overview</h1>
<p>Read-only status from a sanitized snapshot. No changes are sent to the VPN server.</p>
<div class="cards">
<div class="card"><div class="label">Interface</div><div class="value">{interface}</div></div>
<div class="card"><div class="label">Listen port</div><div class="value">{port}</div></div>
<div class="card"><div class="label">Devices</div><div class="value">{data['peer_count']}</div></div>
</div><div class="panel"><h2>Connected identities</h2><table>
<thead><tr><th>Pseudonymous ID</th><th>Allowed IPs</th><th>Last handshake</th>
<th>Received</th><th>Sent</th></tr></thead>
<tbody>{body}</tbody></table></div>
<p class="note">Snapshot time: <code>{collected}</code>. Handshakes do not prove a device is currently online.
Reload to read a fresh snapshot. This prototype must run on localhost or via SSH tunnel only.</p>
</main></body></html>""")
    response.headers.update({
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    })
    return response
