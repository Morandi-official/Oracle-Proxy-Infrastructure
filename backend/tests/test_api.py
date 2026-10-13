import json

from fastapi.testclient import TestClient

from app.main import app


TOKEN = "test-token-" + ("x" * 40)
client = TestClient(app)


def test_health_is_minimal():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "oracle-proxy-api"}


def test_unconfigured_token_fails_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("ORACLE_PROXY_API_TOKEN", raising=False)
    response = client.get("/api/v1/wireguard")
    assert response.status_code == 503


def test_auth_and_sensitive_fields_are_filtered(monkeypatch, tmp_path):
    monkeypatch.setenv("ORACLE_PROXY_API_TOKEN", TOKEN)
    path = tmp_path / "wg0.json"
    path.write_text(json.dumps({
        "interface": "wg0",
        "listen_port": 51820,
        "collected_at": "2026-10-13T01:00:00Z",
        "private_key": "DO_NOT_LEAK",
        "peers": [{
            "id": "abcd",
            "allowed_ips": ["10.77.0.2/32"],
            "latest_handshake": 123,
            "rx_bytes": 12,
            "tx_bytes": 34,
            "public_key": "UNNECESSARY_PUBLIC_KEY",
            "endpoint": "REAL_USER_IP",
            "private_key": "DO_NOT_LEAK",
        }],
    }), encoding="utf-8")
    monkeypatch.setenv("ORACLE_PROXY_SNAPSHOT_PATH", str(path))

    assert client.get("/api/v1/wireguard").status_code == 401
    assert client.get("/api/v1/wireguard", headers={"Authorization": "Bearer wrong"}).status_code == 401

    response = client.get("/api/v1/wireguard", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200
    data = response.json()
    assert data["peer_count"] == 1
    assert data["peers"][0]["rx_bytes"] == 12
    serialized = response.text
    assert "DO_NOT_LEAK" not in serialized
    assert "REAL_USER_IP" not in serialized
    assert "UNNECESSARY_PUBLIC_KEY" not in serialized


def test_missing_snapshot_is_not_public(monkeypatch, tmp_path):
    monkeypatch.setenv("ORACLE_PROXY_API_TOKEN", TOKEN)
    monkeypatch.setenv("ORACLE_PROXY_SNAPSHOT_PATH", str(tmp_path / "absent.json"))
    assert client.get("/api/v1/wireguard", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 503
