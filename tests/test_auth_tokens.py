
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.api.auth.routes import get_current_user
from app.core.security import create_access_token
from app.main import app
from app.models.user import UserRole


def create_user_and_login(client, email="tokens@example.com"):
    payload = {
        "full_name": "Token Test User",
        "email": email,
        "password": "StrongPass123!",
    }

    register_response = client.post("/auth/register", json=payload)
    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        data={
            "username": email,
            "password": "StrongPass123!",
        },
    )
    assert login_response.status_code == 200

    return login_response.json()


def test_refresh_token_success(client):
    tokens = create_user_and_login(client)

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 200
    refreshed = response.json()
    assert refreshed["access_token"]
    assert refreshed["refresh_token"]
    assert refreshed["refresh_token"] != tokens["refresh_token"]


def test_old_refresh_token_cannot_be_reused(client):
    tokens = create_user_and_login(client, "rotate@example.com")

    first_refresh = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert first_refresh.status_code == 200

    second_refresh = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert second_refresh.status_code == 401


def test_logout_success(client):
    tokens = create_user_and_login(client, "logout@example.com")

    response = client.post(
        "/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Logged out successfully"


def test_logout_requires_authentication(client):
    response = client.post(
        "/auth/logout",
        json={"refresh_token": "invalid-token"},
    )

    assert response.status_code == 401


def test_refresh_rejects_invalid_token(client):
    response = client.post(
        "/auth/refresh",
        json={"refresh_token": "invalid-token"},
    )

    assert response.status_code == 401


def test_refresh_rejects_access_token(client):
    tokens = create_user_and_login(client, "wrongtype@example.com")

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["access_token"]},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token required"


def test_current_user_rejects_refresh_token(client):
    tokens = create_user_and_login(client, "refreshasaccess@example.com")

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Access token required"


def test_login_rejects_wrong_password(client):
    create_user_and_login(client, "wrongpassword@example.com")

    response = client.post(
        "/auth/login",
        data={
            "username": "wrongpassword@example.com",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401


def test_register_rejects_duplicate_email(client):
    create_user_and_login(client, "duplicate@example.com")

    response = client.post(
        "/auth/register",
        json={
            "full_name": "Duplicate User",
            "email": "duplicate@example.com",
            "password": "StrongPass123!",
        },
    )

    assert response.status_code == 409


def test_logout_rejects_another_users_refresh_token(client):
    first = create_user_and_login(client, "firstuser@example.com")
    second = create_user_and_login(client, "seconduser@example.com")

    response = client.post(
        "/auth/logout",
        json={"refresh_token": second["refresh_token"]},
        headers={"Authorization": f"Bearer {first['access_token']}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Refresh token does not belong to this user"
    )


def test_logout_rejects_already_revoked_refresh_token(client):
    tokens = create_user_and_login(client, "revokedlogout@example.com")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    payload = {"refresh_token": tokens["refresh_token"]}

    first_response = client.post(
        "/auth/logout",
        json=payload,
        headers=headers,
    )
    assert first_response.status_code == 200

    second_response = client.post(
        "/auth/logout",
        json=payload,
        headers=headers,
    )

    assert second_response.status_code == 401
    assert response_detail(second_response) == (
        "Refresh token is already revoked or unknown"
    )


def response_detail(response):
    return response.json()["detail"]


def test_account_status_rejects_non_admin(client):
    tokens = create_user_and_login(client, "nonadmin@example.com")

    response = client.patch(
        "/auth/users/999/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Only Super Admin can manage account status"
    )


def test_admin_cannot_change_own_account_status(client):
    user_response = client.post(
        "/auth/register",
        json={
            "full_name": "Self Status User",
            "email": "selfstatus@example.com",
            "password": "StrongPass123!",
        },
    )
    assert user_response.status_code == 201
    user_id = user_response.json()["id"]

    admin = SimpleNamespace(id=user_id, role=UserRole.SUPER_ADMIN)
    app.dependency_overrides[get_current_user] = lambda: admin

    try:
        response = client.patch(
            f"/auth/users/{user_id}/status",
            json={"is_active": False},
        )
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "You cannot change your own account status"
    )


def test_admin_cannot_update_missing_user(client):
    tokens = create_user_and_login(client, "adminmissing@example.com")

    admin = SimpleNamespace(id=99999, role=UserRole.SUPER_ADMIN)
    app.dependency_overrides[get_current_user] = lambda: admin

    try:
        response = client.patch(
            "/auth/users/99998/status",
            json={"is_active": False},
        )
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_refresh_rejects_expired_stored_token(client, monkeypatch):
    tokens = create_user_and_login(client, "expiredtoken@example.com")

    future = datetime.now(timezone.utc) + timedelta(days=10)

    # Keep fromtimestamp working normally while making the expiry check
    # see a future current time.
    real_datetime = datetime

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is not None:
                return future.astimezone(tz)
            return future.replace(tzinfo=None)

    monkeypatch.setattr(
        "app.api.auth.routes.datetime",
        FutureDateTime,
    )

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token has expired"


def test_admin_deactivation_disables_user_and_revokes_tokens(client):
    registration = client.post(
        "/auth/register",
        json={
            "full_name": "Account Status User",
            "email": "deactivate@example.com",
            "password": "StrongPass123!",
        },
    )
    assert registration.status_code == 201
    target_user_id = registration.json()["id"]

    login_response = client.post(
        "/auth/login",
        data={
            "username": "deactivate@example.com",
            "password": "StrongPass123!",
        },
    )
    assert login_response.status_code == 200
    tokens = login_response.json()

    admin = SimpleNamespace(id=99999, role=UserRole.SUPER_ADMIN)
    app.dependency_overrides[get_current_user] = lambda: admin

    try:
        response = client.patch(
            f"/auth/users/{target_user_id}/status",
            json={"is_active": False},
        )
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert response.status_code == 200
    assert response.json()["is_active"] is False

    me_response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert me_response.status_code == 401

    refresh_response = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh_response.status_code == 401
def test_current_user_rejects_invalid_subject(client):
    from jose import jwt
    from app.core.config import settings

    token = jwt.encode(
        {
            "sub": "not-an-integer",
            "type": "access",
            "role": "security_analyst",
        },
        settings.secret_key,
        algorithm="HS256",
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired access token"


def test_current_user_rejects_missing_subject(client):
    from jose import jwt
    from app.core.config import settings

    token = jwt.encode(
        {"type": "access", "role": "security_analyst"},
        settings.secret_key,
        algorithm="HS256",
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_current_user_rejects_nonexistent_user(client):
    token = create_access_token(999999, "security_analyst")

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "User not found or inactive"


def test_refresh_rejects_inactive_user(client):
    from sqlalchemy import select
    from app.db.database import get_db
    from app.models.user import RefreshToken, User

    tokens = create_user_and_login(client, "inactive-refresh@example.com")

    # Find the database session supplied by the test fixture.
    db_dependency = app.dependency_overrides[get_db]
    generator = db_dependency()
    db = next(generator)

    try:
        user = db.scalar(
            select(User).where(User.email == "inactive-refresh@example.com")
        )
        assert user is not None
        user.is_active = False
        db.commit()
    finally:
        try:
            next(generator)
        except StopIteration:
            pass

    response = client.post(
        "/auth/refresh",
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "User not found or inactive"


def test_logout_rejects_access_token_as_refresh_token(client):
    tokens = create_user_and_login(client, "logout-wrongtype@example.com")

    response = client.post(
        "/auth/logout",
        json={"refresh_token": tokens["access_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token required"


def test_logout_rejects_invalid_subject(client):
    from jose import jwt
    from app.core.config import settings

    tokens = create_user_and_login(client, "logout-invalid-sub@example.com")

    malformed_refresh = jwt.encode(
        {
            "sub": "not-an-integer",
            "type": "refresh",
        },
        settings.secret_key,
        algorithm="HS256",
    )

    response = client.post(
        "/auth/logout",
        json={"refresh_token": malformed_refresh},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token"

def test_get_current_user_profile_success(client):
    tokens = create_user_and_login(client, "profile-success@example.com")

    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        },
    )

    assert response.status_code == 200
    assert response.json()["email"] == "profile-success@example.com"
    assert response.json()["full_name"] == "Token Test User"