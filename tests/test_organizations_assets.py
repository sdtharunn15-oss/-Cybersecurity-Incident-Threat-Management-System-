from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.api.auth.routes import get_current_user
from app.db.database import Base
from app.main import app
from app.models import UserRole
from app.models.organization import AssetType, AssetCriticality, AssetStatus


def register_user(client, email="tester@example.com"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Test User",
            "email": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 201
    return response.json()


def login(client, email="tester@example.com"):
    response = client.post(
        "/auth/login",
        data={
            "username": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def use_admin_role(user_id):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=UserRole.SUPER_ADMIN,
    )


def create_organization(client, name="Test Organization"):
    response = client.post(
        "/organizations",
        json={"name": name, "description": "Test organization"},
    )
    assert response.status_code == 201
    return response.json()


def create_department(client, organization_id, name="IT Department"):
    response = client.post(
        "/organizations/departments",
        json={
            "name": name,
            "description": "Test department",
            "organization_id": organization_id,
        },
    )
    assert response.status_code == 201
    return response.json()


def create_asset(client, organization_id, department_id, asset_tag="ASSET-001"):
    return client.post(
        "/assets",
        json={
            "name": "Test Server",
            "asset_tag": asset_tag,
            "asset_type": next(iter(AssetType)).value,
            "description": "Test asset",
            "criticality": AssetCriticality.MEDIUM.value,
            "status": AssetStatus.ACTIVE.value,
            "organization_id": organization_id,
            "department_id": department_id,
        },
    )


def test_organization_creation_and_name_trimming(client):
    user = register_user(client)
    use_admin_role(user["id"])

    response = client.post(
        "/organizations",
        json={"name": "  Acme Security  ", "description": "Security team"},
    )

    assert response.status_code == 201
    assert response.json()["name"] == "Acme Security"
    assert response.json()["is_active"] is True


def test_duplicate_organization_returns_conflict(client):
    user = register_user(client)
    use_admin_role(user["id"])

    create_organization(client, "Acme Security")
    response = client.post(
        "/organizations",
        json={"name": "Acme Security"},
    )

    assert response.status_code == 409


def test_analyst_cannot_create_organization(client):
    register_user(client)
    token = login(client)

    response = client.post(
        "/organizations",
        json={"name": "Restricted Organization"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_list_organizations_requires_authentication(client):
    response = client.get("/organizations")
    assert response.status_code == 401


def test_create_and_list_departments(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)

    department = create_department(client, organization["id"])

    assert department["name"] == "IT Department"
    assert department["organization_id"] == organization["id"]

    response = client.get(
        f"/organizations/{organization['id']}/departments"
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == department["id"]


def test_duplicate_department_returns_conflict(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)

    create_department(client, organization["id"], "IT Department")
    response = client.post(
        "/organizations/departments",
        json={
            "name": "IT Department",
            "organization_id": organization["id"],
        },
    )

    assert response.status_code == 409


def test_department_for_missing_organization_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    response = client.post(
        "/organizations/departments",
        json={"name": "IT Department", "organization_id": 9999},
    )

    assert response.status_code == 404


def test_create_asset_and_view_initial_history(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    response = create_asset(client, organization["id"], department["id"])

    assert response.status_code == 201
    asset = response.json()
    assert asset["asset_tag"] == "ASSET-001"
    assert asset["organization_id"] == organization["id"]
    assert asset["department_id"] == department["id"]

    history_response = client.get(f"/assets/{asset['id']}/history")
    assert history_response.status_code == 200
    history = history_response.json()
    assert len(history) == 1
    assert history[0]["previous_status"] is None
    assert history[0]["new_status"] == AssetStatus.ACTIVE.value


def test_duplicate_asset_tag_returns_conflict(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    first = create_asset(client, organization["id"], department["id"])
    second = create_asset(client, organization["id"], department["id"])

    assert first.status_code == 201
    assert second.status_code == 409


def test_asset_rejects_department_from_another_organization(client):
    user = register_user(client)
    use_admin_role(user["id"])
    first_org = create_organization(client, "Organization One")
    second_org = create_organization(client, "Organization Two")
    department = create_department(client, second_org["id"])

    response = create_asset(
        client,
        first_org["id"],
        department["id"],
        "ASSET-WRONG-DEPT",
    )

    assert response.status_code == 400


def test_asset_search_and_filter(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(
        client, organization["id"], department["id"], "WEB-SERVER-01"
    )
    assert created.status_code == 201

    search_response = client.get("/assets", params={"q": "WEB-SERVER"})
    assert search_response.status_code == 200
    assert len(search_response.json()) == 1
    assert search_response.json()[0]["asset_tag"] == "WEB-SERVER-01"

    filtered_response = client.get(
        "/assets",
        params={"organization_id": organization["id"], "page": 1, "page_size": 10},
    )
    assert filtered_response.status_code == 200
    assert len(filtered_response.json()) == 1


def test_update_asset_status_creates_history(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])
    created = create_asset(client, organization["id"], department["id"])
    asset = created.json()

    new_status = next(
        status for status in AssetStatus if status != AssetStatus.ACTIVE
    )
    response = client.patch(
        f"/assets/{asset['id']}/status",
        json={"status": new_status.value, "reason": "Testing status update"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == new_status.value

    history_response = client.get(f"/assets/{asset['id']}/history")
    assert history_response.status_code == 200
    assert len(history_response.json()) == 2
    assert history_response.json()[1]["reason"] == "Testing status update"


def test_get_missing_asset_returns_not_found(client):
    user = register_user(client)
    token = login(client)

    response = client.get(
        "/assets/9999",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


def test_asset_creation_requires_management_permission(client):
    register_user(client)
    token = login(client)

    response = client.post(
        "/assets",
        json={
            "name": "Restricted Server",
            "asset_tag": "RESTRICTED-01",
            "asset_type": next(iter(AssetType)).value,
            "organization_id": 1,
            "department_id": 1,
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_invalid_asset_pagination_returns_validation_error(client):
    user = register_user(client)
    token = login(client)

    response = client.get(
        "/assets",
        params={"page": 0},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422

def test_create_asset_with_missing_organization_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    response = client.post(
        "/assets",
        json={
            "name": "Missing Organization Server",
            "asset_tag": "ASSET-MISSING-ORG",
            "asset_type": next(iter(AssetType)).value,
            "organization_id": 9999,
            "department_id": 9999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Active organization not found"


def test_create_asset_with_missing_owner_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    response = client.post(
        "/assets",
        json={
            "name": "Invalid Owner Server",
            "asset_tag": "ASSET-INVALID-OWNER",
            "asset_type": next(iter(AssetType)).value,
            "organization_id": organization["id"],
            "department_id": department["id"],
            "owner_id": 9999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Active asset owner not found"


def test_list_department_assets(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(
        client, organization["id"], department["id"], "DEPARTMENT-ASSET-01"
    )
    assert created.status_code == 201

    response = client.get(f"/assets/department/{department['id']}")

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["asset_tag"] == "DEPARTMENT-ASSET-01"


def test_list_assets_for_missing_department_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    response = client.get("/assets/department/9999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Department not found"


def test_get_existing_asset(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(
        client, organization["id"], department["id"], "ASSET-GET-01"
    )
    assert created.status_code == 201

    response = client.get(f"/assets/{created.json()['id']}")

    assert response.status_code == 200
    assert response.json()["asset_tag"] == "ASSET-GET-01"


def test_update_asset_status_to_same_status_does_not_add_history(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(client, organization["id"], department["id"])
    asset = created.json()

    response = client.patch(
        f"/assets/{asset['id']}/status",
        json={"status": AssetStatus.ACTIVE.value},
    )

    assert response.status_code == 200
    assert response.json()["status"] == AssetStatus.ACTIVE.value

    history = client.get(f"/assets/{asset['id']}/history")
    assert history.status_code == 200
    assert len(history.json()) == 1


def test_update_asset_status_for_missing_asset_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    new_status = next(
        status for status in AssetStatus if status != AssetStatus.ACTIVE
    )

    response = client.patch(
        "/assets/9999/status",
        json={"status": new_status.value, "reason": "Test"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_update_asset_owner_and_clear_owner(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(client, organization["id"], department["id"])
    asset_id = created.json()["id"]

    assign_response = client.patch(
        f"/assets/{asset_id}/owner",
        json={"owner_id": user["id"]},
    )

    assert assign_response.status_code == 200
    assert assign_response.json()["owner_id"] == user["id"]

    clear_response = client.patch(
        f"/assets/{asset_id}/owner",
        json={"owner_id": None},
    )

    assert clear_response.status_code == 200
    assert clear_response.json()["owner_id"] is None


def test_update_asset_owner_with_invalid_owner_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(client, organization["id"], department["id"])

    response = client.patch(
        f"/assets/{created.json()['id']}/owner",
        json={"owner_id": 9999},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Active asset owner not found"


def test_update_owner_for_missing_asset_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    response = client.patch(
        "/assets/9999/owner",
        json={"owner_id": None},
    )

    assert response.status_code == 404


def test_update_asset_criticality(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(client, organization["id"], department["id"])
    asset_id = created.json()["id"]

    new_criticality = next(
        value
        for value in AssetCriticality
        if value != AssetCriticality.MEDIUM
    )

    response = client.patch(
        f"/assets/{asset_id}/criticality",
        json={"criticality": new_criticality.value},
    )

    assert response.status_code == 200
    assert response.json()["criticality"] == new_criticality.value


def test_update_criticality_for_missing_asset_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    new_criticality = next(iter(AssetCriticality))

    response = client.patch(
        "/assets/9999/criticality",
        json={"criticality": new_criticality.value},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_asset_history_for_missing_asset_returns_not_found(client):
    user = register_user(client)
    use_admin_role(user["id"])

    response = client.get("/assets/9999/history")

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_asset_list_supports_pagination(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    first = create_asset(
        client, organization["id"], department["id"], "PAGE-ASSET-01"
    )
    second = create_asset(
        client, organization["id"], department["id"], "PAGE-ASSET-02"
    )

    assert first.status_code == 201
    assert second.status_code == 201

    page_one = client.get(
        "/assets",
        params={"page": 1, "page_size": 1},
    )
    page_two = client.get(
        "/assets",
        params={"page": 2, "page_size": 1},
    )

    assert page_one.status_code == 200
    assert page_two.status_code == 200
    assert len(page_one.json()) == 1
    assert len(page_two.json()) == 1
    assert page_one.json()[0]["id"] != page_two.json()[0]["id"]


def test_asset_list_filters_by_status_and_criticality(client):
    user = register_user(client)
    use_admin_role(user["id"])
    organization = create_organization(client)
    department = create_department(client, organization["id"])

    created = create_asset(
        client, organization["id"], department["id"], "FILTER-ASSET-01"
    )
    assert created.status_code == 201

    response = client.get(
        "/assets",
        params={
            "status": AssetStatus.ACTIVE.value,
            "criticality": AssetCriticality.MEDIUM.value,
            "asset_type": next(iter(AssetType)).value,
        },
    )

    assert response.status_code == 200
    assert any(
        asset["id"] == created.json()["id"]
        for asset in response.json()
    )


def test_asset_list_rejects_page_size_above_limit(client):
    user = register_user(client)
    token = login(client)

    response = client.get(
        "/assets",
        params={"page_size": 101},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422