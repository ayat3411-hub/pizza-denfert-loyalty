"""Backend test cases for menu revision/auto-sync feature.

Coverage:
- GET /api/menu/version baseline
- POST /api/admin/menu (create) bumps rev and count
- PATCH /api/admin/menu/{id} bumps rev
- DELETE /api/admin/menu/{id} bumps rev and decrements count
- GET /api/menu reflects added/deleted items
"""
import os
import time
import uuid
import pytest
import requests

BASE_URL = (os.environ.get("EXPO_PUBLIC_BACKEND_URL")
            or "https://loyalty-kiosk-tablet.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@pizzadenfert.fr"
ADMIN_PASSWORD = "Admin1234!"


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=20)
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    return r.json()["token"]


@pytest.fixture(scope="module")
def hdr(admin_token):
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


# ---- Helpers ----
def _version():
    r = requests.get(f"{BASE_URL}/api/menu/version", timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    assert "rev" in j and "count" in j
    assert isinstance(j["rev"], int)
    assert isinstance(j["count"], int)
    return j


def test_version_baseline():
    j = _version()
    assert j["rev"] >= 0
    assert j["count"] >= 0


def test_menu_list_returns_array():
    r = requests.get(f"{BASE_URL}/api/menu", timeout=15)
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    # Ensure mongodb _id is not leaked
    for it in items[:5]:
        assert "_id" not in it


def test_create_bumps_rev_and_count(hdr):
    before = _version()
    name = f"TEST_Probe_{uuid.uuid4().hex[:8]}"
    payload = {"category": "desserts", "name": name, "price": 4.5,
               "desc_fr": "test", "desc_en": "test"}
    r = requests.post(f"{BASE_URL}/api/admin/menu", json=payload, headers=hdr, timeout=15)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["name"] == name
    assert created["category"] == "desserts"
    item_id = created["id"]
    try:
        after = _version()
        assert after["rev"] == before["rev"] + 1, f"expected +1, got {before['rev']}->{after['rev']}"
        assert after["count"] == before["count"] + 1
        # GET /api/menu reflects new item
        r2 = requests.get(f"{BASE_URL}/api/menu", timeout=15)
        names = [m["name"] for m in r2.json()]
        assert name in names

        # PATCH bumps rev
        rp = requests.patch(f"{BASE_URL}/api/admin/menu/{item_id}",
                            json={"price": 5.0}, headers=hdr, timeout=15)
        assert rp.status_code == 200, rp.text
        assert rp.json()["price"] == 5.0
        after2 = _version()
        assert after2["rev"] == after["rev"] + 1
        assert after2["count"] == after["count"]  # count unchanged
    finally:
        # Cleanup: DELETE bumps rev and decrements count
        rd = requests.delete(f"{BASE_URL}/api/admin/menu/{item_id}", headers=hdr, timeout=15)
        assert rd.status_code == 200, rd.text
        assert rd.json().get("deleted") is True
        final = _version()
        # final rev should be greater than before (at least +3 from create/patch/delete)
        assert final["rev"] >= before["rev"] + 3
        assert final["count"] == before["count"]
        # GET /api/menu no longer contains item
        r3 = requests.get(f"{BASE_URL}/api/menu", timeout=15)
        assert name not in [m["name"] for m in r3.json()]


def test_delete_nonexistent_returns_404(hdr):
    r = requests.delete(f"{BASE_URL}/api/admin/menu/does-not-exist-xyz", headers=hdr, timeout=15)
    assert r.status_code == 404


def test_admin_endpoints_require_auth():
    # No token
    r = requests.post(f"{BASE_URL}/api/admin/menu",
                      json={"category": "desserts", "name": "x", "price": 1.0}, timeout=15)
    assert r.status_code in (401, 403)
