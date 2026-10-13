"""Read-only Chinese dashboard for local development / protected SSH tunneling.

No cookies, scripts or third-party resources. HTTP Basic password matches
ORACLE_PROXY_API_TOKEN and must NEVER be sent over public unencrypted HTTP.
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
body{margin:0;background:#0d111b;color:#edf1fa;line-height:1.55}
main{max-width:1100px;margin:42px auto;padding:0 24px}
h1{font-size:clamp(25px,4vw,38px);margin:6px 0 10px}
h2{font-size:18px}
p{color:#a9b7d0}
.topline{color:#8dbdff;font-size:13px;letter-spacing:0.08em;font-weight:700}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:28px 0}
.card,.panel{border:1px solid #29364b;background:#161e2c;border-radius:14px;padding:18px}
.card .label{color:#a9b7d0;font-size:13px;margin-bottom:9px}
.card .value{font-size:25px;font-weight:700;overflow-wrap:anywhere}
.panel{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:680px}
td,th{border-bottom:1px solid #29364b;text-align:left;padding:13px 11px;font-size:13px}
th{color:#a9b7d0;font-weight:600}
tbody tr:last-child td{border-bottom:0}
.note{font-size:13px;margin-top:18px}
code{color:#a8d4ff}
.status{font-size:13px;border-radius:8px;padding:7px 10px;display:inline-block}
.fresh{background:#173d31;color:#a4edce}
.stale{background:#49361d;color:#ffe1a2}
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
            return "从未握手"
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OverflowError, OSError):
        return "未知"


def _freshness(value: object) -> tuple[str, str]:
    """Conservatively label *snapshot age*, not peer 'online' status."""
    if not isinstance(value, str):
        return ("采集时间未知", "stale")
    try:
        snapshot_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if snapshot_at.tzinfo is None:
            return ("采集时间缺少时区", "stale")
        seconds = (datetime.now(timezone.utc) - snapshot_at).total_seconds()
    except (OverflowError, TypeError, ValueError):
        return ("采集时间无效", "stale")
    if -60 <= seconds <= 180:
        return ("快照时间较近", "fresh")
    return ("快照已过期或为演示数据", "stale")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(authorization: str | None = Header(default=None)) -> HTMLResponse:
    _require_basic(authorization)
    data = wireguard_overview()
    rows = []
    rx_total = 0
    tx_total = 0
    for peer in data["peers"]:
        address_list = peer.get("allowed_ips", [])
        addresses = ", ".join(str(x) for x in address_list) if isinstance(address_list, list) else "—"
        rx = peer.get("rx_bytes", 0)
        tx = peer.get("tx_bytes", 0)
        # Only sum validated nonnegative integer counters.
        if isinstance(rx, int) and not isinstance(rx, bool) and rx >= 0:
            rx_total += rx
        if isinstance(tx, int) and not isinstance(tx, bool) and tx >= 0:
            tx_total += tx
        fields = (
            peer.get("id", "—"),
            addresses,
            _fmt_handshake(peer.get("latest_handshake", 0)),
            _fmt_bytes(rx),
            _fmt_bytes(tx),
        )
        rows.append("<tr>" + "".join(f"<td>{escape(str(field))}</td>" for field in fields) + "</tr>")

    body = "\n".join(rows) if rows else '<tr><td colspan="5">此快照中没有设备</td></tr>'
    interface = escape(str(data.get("interface", "—")))
    port = escape(str(data.get("listen_port", "—")))
    collected = escape(str(data.get("collected_at", "—")))
    freshness, freshness_class = _freshness(data.get("collected_at"))
    rx_total_display, tx_total_display = _fmt_bytes(rx_total), _fmt_bytes(tx_total)
    response = HTMLResponse(f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Oracle Proxy · 只读管理面板</title>
<style>{_STYLES}</style></head>
<body><main><div class="topline">ORACLE PROXY / INFRASTRUCTURE</div>
<h1>WireGuard 管理概览</h1>
<p>只读管理原型。数据来自脱敏快照，不会更改 Oracle VPN 服务器。</p>
<span class="status {freshness_class}">{escape(freshness)}</span>
<div class="cards">
<div class="card"><div class="label">隧道接口</div><div class="value">{interface}</div></div>
<div class="card"><div class="label">监听端口</div><div class="value">{port}</div></div>
<div class="card"><div class="label">已配置设备</div><div class="value">{data['peer_count']}</div></div>
<div class="card"><div class="label">累计接收</div><div class="value">{rx_total_display}</div></div>
<div class="card"><div class="label">累计发送</div><div class="value">{tx_total_display}</div></div>
</div><div class="panel"><h2>设备与最近握手记录</h2><table>
<thead><tr><th>脱敏设备标识</th><th>隧道 IP</th><th>上一次握手</th>
<th>接收流量</th><th>发送流量</th></tr></thead>
<tbody>{body}</tbody></table></div>
<p class="note">采集时间：<code>{collected}</code>。握手时间不等于设备始终在线。
演示数据不是真实服务器统计。刷新页面可重新读取最新快照。
此原型仅可在本机或安全的 SSH 隧道内使用。</p>
</main></body></html>""")
    response.headers.update({
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    })
    return response
