from types import SimpleNamespace

import pytest

from app import collector


def test_collector_uses_only_public_status_and_hashes_keys(monkeypatch):
    key = "a-public-key-used-for-testing"
    records = {
        "listen-port": "51820\n",
        "allowed-ips": f"{key}\t10.77.0.2/32\n",
        "latest-handshakes": f"{key}\t1690000000\n",
        "transfer": f"{key}\t1234\t5678\n",
    }
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout=records[argv[-1]])

    monkeypatch.setattr(collector.subprocess, "run", fake_run)
    result = collector.collect_snapshot("wg0")
    assert result["listen_port"] == 51820
    assert result["peers"][0]["rx_bytes"] == 1234
    assert result["peers"][0]["allowed_ips"] == ["10.77.0.2/32"]
    assert key not in str(result)
    assert len(calls) == 4
    assert all(item[:3] == ["wg", "show", "wg0"] for item in calls)
    assert all(item[-1] != "dump" for item in calls)


def test_collector_rejects_invalid_interface():
    with pytest.raises(ValueError):
        collector.collect_snapshot("wg0;rm -rf /")


def test_atomic_snapshot_permissions(tmp_path):
    target = tmp_path / "status.json"
    collector.write_snapshot({"peers": []}, target)
    assert target.read_text(encoding="utf-8").strip() == '{"peers":[]}'
    assert target.stat().st_mode & 0o777 == 0o600
