from fastapi import status

from tests.api import client
from tests.api.helpers import create_core, delete_core, get_inbounds, unique_name


def test_host_create(access_token):
    """Test that the host create route is accessible."""

    core = create_core(access_token)
    inbounds = get_inbounds(access_token)
    assert inbounds, "No inbounds available for host creation"
    created_hosts = []

    try:
        for idx, inbound in enumerate(inbounds[:3]):
            payload = {
                "remark": unique_name(f"test_host_{idx}"),
                "address": ["127.0.0.1"],
                "port": 443,
                "sni": [f"test_sni_{idx}.com"],
                "inbound_tag": inbound,
                "priority": idx + 1,
                "vless_route": "6967" if idx == 0 else None,  # Only test vless_route on the first host
            }
            response = client.post(
                "/api/host",
                headers={"Authorization": f"Bearer {access_token}"},
                json=payload,
            )
            assert response.status_code == status.HTTP_201_CREATED
            created_hosts.append(response.json()["id"])
            assert response.json()["remark"] == payload["remark"]
            assert response.json()["address"] == payload["address"]
            assert response.json()["port"] == payload["port"]
            assert response.json()["sni"] == payload["sni"]
            assert response.json()["inbound_tag"] == inbound
    finally:
        for host_id in created_hosts:
            client.delete(f"/api/host/{host_id}", headers={"Authorization": f"Bearer {access_token}"})
        delete_core(access_token, core["id"])


def test_host_get(access_token):
    """Test that the host get route is accessible."""

    core = create_core(access_token)
    inbound_list = get_inbounds(access_token)
    assert inbound_list, "No inbounds available for host reads"
    inbound = inbound_list[0]
    payload = {
        "remark": unique_name("test_host_get"),
        "address": ["127.0.0.1"],
        "port": 443,
        "sni": ["test_sni_get.com"],
        "inbound_tag": inbound,
        "priority": 1,
    }
    create_response = client.post("/api/host", headers={"Authorization": f"Bearer {access_token}"}, json=payload)
    host_id = create_response.json()["id"]
    response = client.get(
        "/api/hosts",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == status.HTTP_200_OK
    assert any(host["remark"] == payload["remark"] for host in response.json())
    client.delete(f"/api/host/{host_id}", headers={"Authorization": f"Bearer {access_token}"})
    delete_core(access_token, core["id"])


def test_host_update(access_token):
    """Test that the host update route is accessible."""

    core = create_core(access_token)
    inbound_list = get_inbounds(access_token)
    assert inbound_list, "No inbounds available for host updates"
    inbound = inbound_list[0]
    create_response = client.post(
        "/api/host",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "remark": unique_name("test_host_update"),
            "address": ["127.0.0.1"],
            "port": 443,
            "sni": ["test_sni.com"],
            "inbound_tag": inbound,
            "priority": 1,
        },
    )
    host_id = create_response.json()["id"]
    response = client.put(
        f"/api/host/{host_id}",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "remark": "test_host_updated",
            "priority": 666,
            "address": ["127.0.0.2"],
            "port": 443,
            "sni": ["test_sni_updated.com"],
            "inbound_tag": "Trojan Websocket TLS",
        },
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["remark"] == "test_host_updated"
    assert response.json()["address"] == ["127.0.0.2"]
    assert response.json()["port"] == 443
    assert response.json()["sni"] == ["test_sni_updated.com"]
    assert response.json()["priority"] == 666
    assert response.json()["inbound_tag"] == "Trojan Websocket TLS"
    client.delete(f"/api/host/{host_id}", headers={"Authorization": f"Bearer {access_token}"})
    delete_core(access_token, core["id"])


def test_host_tls_min_max_version_create_and_update(access_token):
    """Test that tls_min_version and tls_max_version are accepted and returned."""
    core = create_core(access_token)
    inbounds = get_inbounds(access_token)
    assert inbounds, "No inbounds available for host creation"
    inbound = inbounds[0]
    remark = unique_name("test_host_tls_versions")
    try:
        create_payload = {
            "remark": remark,
            "address": ["127.0.0.1"],
            "port": 443,
            "sni": ["tlsversions.example.com"],
            "inbound_tag": inbound,
            "priority": 9998,
            "security": "tls",
            "tls_min_version": "1.2",
            "tls_max_version": "1.3",
        }
        create_resp = client.post(
            "/api/host",
            headers={"Authorization": f"Bearer {access_token}"},
            json=create_payload,
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        data = create_resp.json()
        assert data.get("tls_min_version") == "1.2"
        assert data.get("tls_max_version") == "1.3"

        host_id = data["id"]
        update_payload = {
            "remark": data["remark"],
            "priority": data["priority"],
            "address": data["address"],
            "sni": data["sni"],
            "inbound_tag": data["inbound_tag"],
            "security": "tls",
            "tls_min_version": "1.1",
            "tls_max_version": "1.2",
        }
        update_resp = client.put(
            f"/api/host/{host_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            json=update_payload,
        )
        assert update_resp.status_code == status.HTTP_200_OK
        updated = update_resp.json()
        assert updated.get("tls_min_version") == "1.1"
        assert updated.get("tls_max_version") == "1.2"

        clear_payload = {
            "remark": updated["remark"],
            "priority": updated["priority"],
            "address": updated["address"],
            "sni": updated["sni"],
            "inbound_tag": updated["inbound_tag"],
            "security": "tls",
        }
        clear_resp = client.put(
            f"/api/host/{host_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            json=clear_payload,
        )
        assert clear_resp.status_code == status.HTTP_200_OK
        cleared = clear_resp.json()
        assert cleared.get("tls_min_version") is None
        assert cleared.get("tls_max_version") is None
    finally:
        hosts = client.get("/api/hosts", headers={"Authorization": f"Bearer {access_token}"}).json()
        for h in hosts:
            if h.get("remark") == remark:
                client.delete(f"/api/host/{h['id']}", headers={"Authorization": f"Bearer {access_token}"})
                break
        delete_core(access_token, core["id"])


def test_host_delete(access_token):
    """Test that the host delete route is accessible."""

    core = create_core(access_token)
    inbound_list = get_inbounds(access_token)
    assert inbound_list, "No inbounds available for host deletion"
    inbound = inbound_list[0]
    create_response = client.post(
        "/api/host",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "remark": unique_name("test_host_delete"),
            "address": ["127.0.0.1"],
            "port": 443,
            "sni": ["test_sni_delete.com"],
            "inbound_tag": inbound,
            "priority": 1,
        },
    )
    host_id = create_response.json()["id"]
    response = client.delete(
        f"/api/host/{host_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    delete_core(access_token, core["id"])


# Tests for /api/hosts/simple endpoint


def create_simple_host(access_token: str, inbound_tag: str, *, remark: str, priority: int) -> int:
    payload = {
        "remark": remark,
        "address": ["127.0.0.1"],
        "port": 443,
        "sni": [f"{remark}.example.com"],
        "inbound_tag": inbound_tag,
        "priority": priority,
    }
    response = client.post(
        "/api/host",
        headers={"Authorization": f"Bearer {access_token}"},
        json=payload,
    )
    assert response.status_code == status.HTTP_201_CREATED
    return response.json()["id"]
