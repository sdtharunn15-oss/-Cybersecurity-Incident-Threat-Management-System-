from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy import select

from app.core.security import hash_token
from app.db.database import Base
from app.models.user import PasswordResetToken, RefreshToken, User


def register_test_user(client, email="reset@example.com"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Password Reset User",
            "email": email,
            "password": "OldPassword123!"
        }
    )
    assert response.status_code == 201
    return response.json()


def test_password_reset_request_for_existing_user(client, capsys):
    register_test_user(client, "reset-existing@example.com")

    response = client.post(
        "/auth/password-reset/request",
        json={"email": "reset-existing@example.com"}
    )

    assert response.status_code == 200
    assert "If the account exists" in response.json()["message"]

    output = capsys.readouterr().out
    assert "Password reset token for reset-existing@example.com:" in output


def test_password_reset_request_for_unknown_email(client):
    response = client.post(
        "/auth/password-reset/request",
        json={"email": "unknown@example.com"}
    )

    assert response.status_code == 200
    assert "If the account exists" in response.json()["message"]


def test_password_reset_confirm_rejects_invalid_token(client):
    response = client.post(
        "/auth/password-reset/confirm",
        json={
            "token": "invalid-token",
            "new_password": "NewPassword123!"
        }
    )

    assert response.status_code == 400


def test_password_reset_confirm_success(client, capsys):
    register_test_user(client, "reset-confirm@example.com")

    client.post(
        "/auth/password-reset/request",
        json={"email": "reset-confirm@example.com"}
    )

    output = capsys.readouterr().out
    token = output.strip().split(":", 1)[1].strip()

    response = client.post(
        "/auth/password-reset/confirm",
        json={
            "token": token,
            "new_password": "NewPassword123!"
        }
    )

    assert response.status_code == 200
    assert response.json()["message"] == (
        "Password reset successfully. Please log in again."
    )

    login_response = client.post(
        "/auth/login",
        data={
            "username": "reset-confirm@example.com",
            "password": "NewPassword123!"
        }
    )
    assert login_response.status_code == 200

    old_password_response = client.post(
        "/auth/login",
        data={
            "username": "reset-confirm@example.com",
            "password": "OldPassword123!"
        }
    )
    assert old_password_response.status_code == 401


def test_password_reset_token_cannot_be_reused(client, capsys):
    register_test_user(client, "reset-reuse@example.com")

    client.post(
        "/auth/password-reset/request",
        json={"email": "reset-reuse@example.com"}
    )

    output = capsys.readouterr().out
    token = output.strip().split(":", 1)[1].strip()

    payload = {
        "token": token,
        "new_password": "NewPassword123!"
    }

    first_response = client.post(
        "/auth/password-reset/confirm",
        json=payload
    )
    assert first_response.status_code == 200

    second_response = client.post(
        "/auth/password-reset/confirm",
        json=payload
    )
    assert second_response.status_code == 400


def test_password_reset_rejects_short_new_password(client):
    response = client.post(
        "/auth/password-reset/confirm",
        json={
            "token": "any-token",
            "new_password": "short"
        }
    )

    assert response.status_code == 422
