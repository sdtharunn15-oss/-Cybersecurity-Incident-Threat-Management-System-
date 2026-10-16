
def test_current_user_requires_authentication(client):
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_register_rejects_empty_payload(client):
    response = client.post("/auth/register", json={})

    assert response.status_code == 422


def test_login_rejects_missing_credentials(client):
    response = client.post("/auth/login", data={})

    assert response.status_code == 422
