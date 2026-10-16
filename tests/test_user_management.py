from types import SimpleNamespace

from app.api.auth.routes import get_current_user
from app.main import app
from app.models import UserRole


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


def set_actor(user_id, role):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
    )


def create_managed_user(client, email, role=None):
    payload = {
        "full_name": "Managed Analyst",
        "email": email,
        "password": "ManagedPassword123!",
    }
    if role is not None:
        payload["role"] = role.value

    return client.post("/users", json=payload)


def test_create_managed_user_normalizes_email(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.post(
        "/users",
        json={
            "full_name": "  Managed Analyst  ",
            "email": "  Analyst@Example.com  ",
            "password": "ManagedPassword123!",
            "role": UserRole.SECURITY_ANALYST.value,
        },
    )

    assert response.status_code == 201
    assert response.json()["full_name"] == "Managed Analyst"
    assert response.json()["email"] == "analyst@example.com"
    assert response.json()["role"] == UserRole.SECURITY_ANALYST.value
    assert response.json()["is_active"] is True


def test_create_managed_user_rejects_duplicate_email(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    first = create_managed_user(client, "duplicate@example.com")
    second = create_managed_user(client, "DUPLICATE@example.com")

    assert first.status_code == 201
    assert second.status_code == 409


def test_analyst_cannot_create_managed_user(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SECURITY_ANALYST)

    response = create_managed_user(client, "newuser@example.com")

    assert response.status_code == 403


def test_security_manager_cannot_assign_super_admin_role(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SECURITY_MANAGER)

    response = create_managed_user(
        client,
        "admin@example.com",
        UserRole.SUPER_ADMIN,
    )

    assert response.status_code == 403


def test_list_users_requires_management_permission(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SECURITY_ANALYST)

    response = client.get("/users")

    assert response.status_code == 403


def test_list_users_as_super_admin(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.get("/users")

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_update_user_role(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)
    target = register_user(client, "target@example.com")

    response = client.patch(
        f"/users/{target['id']}/role",
        json={"role": UserRole.IT_ADMINISTRATOR.value},
    )

    assert response.status_code == 200
    assert response.json()["role"] == UserRole.IT_ADMINISTRATOR.value


def test_cannot_change_own_role(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.patch(
        f"/users/{actor['id']}/role",
        json={"role": UserRole.SECURITY_MANAGER.value},
    )

    assert response.status_code == 400


def test_update_missing_user_role_returns_404(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.patch(
        "/users/9999/role",
        json={"role": UserRole.SECURITY_ANALYST.value},
    )

    assert response.status_code == 404


def test_update_user_status(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)
    target = register_user(client, "inactive@example.com")

    response = client.patch(
        f"/users/{target['id']}/status",
        json={"is_active": False},
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False


def test_cannot_deactivate_own_account(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.patch(
        f"/users/{actor['id']}/status",
        json={"is_active": False},
    )

    assert response.status_code == 400


def test_update_missing_user_status_returns_404(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.patch(
        "/users/9999/status",
        json={"is_active": False},
    )

    assert response.status_code == 404


def test_create_and_list_security_teams(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    created = client.post(
        "/security-teams",
        json={
            "name": "  Incident Response  ",
            "description": "Handles incident response",
        },
    )

    assert created.status_code == 201
    assert created.json()["name"] == "Incident Response"

    listed = client.get("/security-teams")

    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] == created.json()["id"]


def test_duplicate_security_team_returns_conflict(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    client.post("/security-teams", json={"name": "Threat Hunting"})
    response = client.post(
        "/security-teams",
        json={"name": "Threat Hunting"},
    )

    assert response.status_code == 409


def test_security_team_rejects_missing_department(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.post(
        "/security-teams",
        json={"name": "Threat Hunting", "department_id": 9999},
    )

    assert response.status_code == 404


def test_assign_analyst_to_security_team(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    analyst = register_user(client, "analyst@example.com")
    team_response = client.post(
        "/security-teams",
        json={"name": "Incident Response"},
    )
    assert team_response.status_code == 201
    team_id = team_response.json()["id"]

    assigned = client.post(
        f"/security-teams/{team_id}/members",
        json={"user_id": analyst["id"]},
    )

    assert assigned.status_code == 201
    assert assigned.json()["team_id"] == team_id
    assert assigned.json()["user_id"] == analyst["id"]

    listed = client.get(f"/security-teams/{team_id}/members")
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_cannot_assign_same_analyst_twice(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    analyst = register_user(client, "analyst@example.com")
    team = client.post(
        "/security-teams",
        json={"name": "Incident Response"},
    ).json()

    first = client.post(
        f"/security-teams/{team['id']}/members",
        json={"user_id": analyst["id"]},
    )
    second = client.post(
        f"/security-teams/{team['id']}/members",
        json={"user_id": analyst["id"]},
    )

    assert first.status_code == 201
    assert second.status_code == 409


def test_cannot_assign_non_analyst_to_team(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    non_analyst = client.post(
        "/users",
        json={
            "full_name": "IT Administrator",
            "email": "itadmin@example.com",
            "password": "ManagedPassword123!",
            "role": UserRole.IT_ADMINISTRATOR.value,
        },
    )
    assert non_analyst.status_code == 201

    team = client.post(
        "/security-teams",
        json={"name": "Incident Response"},
    ).json()

    response = client.post(
        f"/security-teams/{team['id']}/members",
        json={"user_id": non_analyst.json()["id"]},
    )

    assert response.status_code == 400


def test_assign_to_missing_team_returns_404(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)
    analyst = register_user(client, "analyst@example.com")

    response = client.post(
        "/security-teams/9999/members",
        json={"user_id": analyst["id"]},
    )

    assert response.status_code == 404


def test_list_members_for_missing_team_returns_404(client):
    actor = register_user(client)
    set_actor(actor["id"], UserRole.SUPER_ADMIN)

    response = client.get("/security-teams/9999/members")

    assert response.status_code == 404

