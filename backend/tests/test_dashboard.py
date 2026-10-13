import base64
import json

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)
TOKEN = "test-secret-" + "a" * 48


def auth(value=TOKEN):
    value = base64.b64encode(f"admin:{value}".encode()).decode()
    return {"Authorization": "Basic " + value}


def test_dashboard_requires_auth(monkeypatch, tmp_path):
    monkeypatch.setenv("ORACLE_PROXY_API_TOKEN", TOKEN)
    monkeypatch.setenv("ORACLE_PROXY_SNAPSHOT_PATH", str(tmp_path / "missing.json"))
    assert client.get("/dashboard").status_code == 401
    assert client.get("/dashboard", headers=auth("incorrect")).status_code == 401
    assert client.get("/dashboard", headers={"Authorization": "Basic not-base64!"}).status_code == 401
    assert client.get("/dashboard", headers={"Authorization": "Bearer " + TOKEN}).status_code == 401


def test_dashboard_fails_closed_if_not_configured(monkeypatch):
    monkeypatch.delenv("ORACLE_PROXY_API_TOKEN", raising=False)
    assert client.get("/dashboard", headers=auth()).status_code == 503


def test_dashboard_escapes_markup_and_filters_sensitive_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("ORACLE_PROXY_API_TOKEN", TOKEN)
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({
        "interface": 'wg0<script>alert(1)</script>',
        "listen_port": 51820,
        "collected_at": "2026-10-13T01:00:00Z",
        "private_key": "NEVER_SHOW_PRIVATE",
        "peers": [{
            "id": "<b>injected</b>",
            "allowed_ips": ["10.77.0.2/32"],
            "latest_handshake": 0,
            "rx_bytes": 1024,
            "tx_bytes": 2048,
            "endpoint": "NEVER_SHOW_ENDPOINT",
        }],
    }), encoding="utf-8")
    monkeypatch.setenv("ORACLE_PROXY_SNAPSHOT_PATH", str(path))
    response = client.get("/dashboard", headers=auth())
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "1.0 KiB" in response.text
    assert "2.0 KiB" in response.text
    assert "&lt;b&gt;injected&lt;/b&gt;" in response.text
    assert "<b>injected</b>" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "<script>" not in response.text
    assert "NEVER_SHOW_PRIVATE" not in response.text
    assert "NEVER_SHOW_ENDPOINT" not in response.text


def test_dashboard_chinese_and_stale_snapshot(monkeypatch, tmp_path):
    monkeypatch.setenv("ORACLE_PROXY_API_TOKEN", TOKEN)
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({
        "interface": "wg0",
        "listen_port": 51820,
        "collected_at": "2000-01-01T00:00:00Z",
        "peers": [],
    }), encoding="utf-8")
    monkeypatch.setenv("ORACLE_PROXY_SNAPSHOT_PATH", str(path))
    response = client.get("/dashboard", headers=auth())
    assert response.status_code == 200
    assert 'lang="zh-CN"' in response.text
    assert "快照已过期或为演示数据" in response.text
    assert "已配置设备" in response.text
    assert "没有设备" in response.text
    assert "在线设备" not in response.text


def test_freshness_is_a_snapshot_label_not_online_flag():
    from app.dashboard import _freshness
    assert _freshness("invalid")[1] == "stale"
    assert _freshness("2000-01-01T00:00:00Z")[1] == "stale"
