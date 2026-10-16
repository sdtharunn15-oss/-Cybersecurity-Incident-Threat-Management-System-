def register_account(client, email):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Status Test User",
            "email": email,
            "password": "StrongPass123!"
        }
    )
    assert response.status_code == 201
    return response.json()


def login_account(client, email):
    response = client.post(
        "/auth/login",
        data={
            "username": email,
            "password": "StrongPass123!"
        }
    )
    assert response.status_code == 200
    return response.json()


def test_account_status_requires_authentication(client):
    response = client.patch(
        "/auth/users/1/status",
        json={"is_active": False}
    )
    assert response.status_code == 401


def test_non_admin_cannot_change_account_status(client):
    register_account(client, "analyst-status@example.com")
    target = register_account(client, "target-status@example.com")
    tokens = login_account(client, "analyst-status@example.com")

    response = client.patch(
        f"/auth/users/{target['id']}/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    assert response.status_code == 403


def test_user_cannot_deactivate_own_account(client):
    register_account(client, "self-status@example.com")
    tokens = login_account(client, "self-status@example.com")

    # The normal registration endpoint creates an analyst, so this request
    # should be forbidden before the self-status check is reached.
    response = client.patch(
        "/auth/users/1/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    assert response.status_code == 403


def test_account_status_user_not_found(client):
    response = client.patch(
        "/auth/users/9999/status",
        json={"is_active": False}
    )
    assert response.status_code == 401


def test_account_status_rejects_invalid_payload(client):
    register_account(client, "invalid-status@example.com")
    tokens = login_account(client, "invalid-status@example.com")

    response = client.patch(
        "/auth/users/1/status",
        json={},
        headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )

    assert response.status_code == 422
