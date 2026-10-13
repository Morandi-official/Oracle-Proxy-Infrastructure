"""Unprivileged, read-only Oracle Proxy API."""

import hmac
import json
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI(title="Oracle Proxy Infrastructure", version="0.1.0")


def require_admin(authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("ORACLE_PROXY_API_TOKEN", "")
    if len(expected) < 32:
        raise HTTPException(status_code=503, detail="Admin API is not configured")

    scheme, _, candidate = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(candidate, expected):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "oracle-proxy-api"}


@app.get("/api/v1/wireguard", dependencies=[Depends(require_admin)])
def wireguard_overview() -> dict:
    path = Path(os.environ.get("ORACLE_PROXY_SNAPSHOT_PATH", "./data/wg0.json"))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise HTTPException(status_code=503, detail="Status snapshot unavailable")

    if not isinstance(data, dict) or not isinstance(data.get("peers"), list):
        raise HTTPException(status_code=503, detail="Invalid status snapshot")

    # Explicit field allowlist. Never serialize raw WireGuard output or private keys.
    peers = []
    for peer in data["peers"]:
        if not isinstance(peer, dict):
            raise HTTPException(status_code=503, detail="Invalid status snapshot")
        peers.append({
            "id": peer.get("id"),
            "allowed_ips": peer.get("allowed_ips", []),
            "latest_handshake": peer.get("latest_handshake", 0),
            "rx_bytes": peer.get("rx_bytes", 0),
            "tx_bytes": peer.get("tx_bytes", 0),
        })

    return {
        "interface": data.get("interface"),
        "listen_port": data.get("listen_port"),
        "collected_at": data.get("collected_at"),
        "peer_count": len(peers),
        "peers": peers,
    }


# Keep the HTML dashboard in a separate, read-only router.
from .dashboard import router as dashboard_router  # noqa: E402

app.include_router(dashboard_router)
