import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app import models
from app.services.scan_service import get_latest_scan_ids

client = TestClient(app)

def get_admin_token():
    res = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin"})
    assert res.status_code == 200
    return res.json()["access_token"]

def test_inventory_endpoint():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch general inventory
    res = client.get("/api/vulnerabilities/inventory?page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert "stats" in data
    assert data["total"] > 0
    assert len(data["items"]) <= 10

    first = data["items"][0]
    assert "ip_address" in first
    assert "hostname" in first
    assert "os" in first
    assert "critical_count" in first
    assert "high_count" in first
    assert "medium_count" in first
    assert "low_count" in first
    assert "risk_score" in first

    # 2. Filter by search
    res_search = client.get(f"/api/vulnerabilities/inventory?search={first['ip_address']}", headers=headers)
    assert res_search.status_code == 200
    s_data = res_search.json()
    assert s_data["total"] >= 1
    assert any(h["ip_address"] == first["ip_address"] for h in s_data["items"])

    # 3. Filter by severity
    res_crit = client.get("/api/vulnerabilities/inventory?severity_filter=critical", headers=headers)
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    for h in crit_data["items"]:
        assert h["critical_count"] > 0

    # 4. Filter by asset group
    res_group = client.get(f"/api/vulnerabilities/inventory?asset_group_id={first['asset_group_id']}", headers=headers)
    assert res_group.status_code == 200
    g_data = res_group.json()
    assert g_data["total"] >= 1
    for h in g_data["items"]:
        assert h["asset_group_id"] == first["asset_group_id"] or h["asset_group_name"] != ""
