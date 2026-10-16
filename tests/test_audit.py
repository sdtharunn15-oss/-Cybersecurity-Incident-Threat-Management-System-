
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.audit import AuditLog


def register_user(client):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Audit Tester",
            "email": f"audit_{uuid4().hex[:10]}@example.com",
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SUPER_ADMIN):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
    )


def get_test_db():
    return next(app.dependency_overrides[get_db]())


def create_log(
    user_id,
    action="LOGIN",
    resource_type="user",
    resource_id=None,
    description="Test audit log",
):
    db = get_test_db()
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            ip_address="127.0.0.1",
            user_agent="pytest",
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.id
    finally:
        db.close()


def test_create_audit_log_success(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/audit-logs/",
        json={
            "action": "LOGIN",
            "resource_type": "user",
            "resource_id": "123",
            "description": "User logged in",
        },
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["action"] == "LOGIN"
    assert data["resource_type"] == "user"
    assert data["resource_id"] == "123"
    assert data["description"] == "User logged in"
    assert data["user_id"] == user_id
    assert data["ip_address"] is not None
    assert data["user_agent"] is not None


def test_create_audit_log_security_manager(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_MANAGER)

    response = client.post(
        "/audit-logs/",
        json={
            "action": "UPDATE",
            "resource_type": "asset",
        },
    )

    assert response.status_code == 201, response.text


def test_create_audit_log_auditor(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.AUDITOR)

    response = client.post(
        "/audit-logs/",
        json={
            "action": "VIEW",
            "resource_type": "report",
        },
    )

    assert response.status_code == 201, response.text


def test_create_audit_log_forbidden(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_ANALYST)

    response = client.post(
        "/audit-logs/",
        json={
            "action": "LOGIN",
            "resource_type": "user",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


def test_list_audit_logs_success(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_log(user_id, action="LOGIN")
    create_log(user_id, action="LOGOUT")

    response = client.get("/audit-logs/")

    assert response.status_code == 200, response.text
    assert len(response.json()) >= 2


def test_list_audit_logs_filter_user_id(client):
    user_id = register_user(client)
    other_user_id = register_user(client)
    set_actor(user_id)

    create_log(user_id, action="LOGIN")
    create_log(other_user_id, action="UPDATE")

    response = client.get(
        "/audit-logs/",
        params={"user_id": other_user_id},
    )

    assert response.status_code == 200, response.text
    assert all(
        item["user_id"] == other_user_id
        for item in response.json()
    )


def test_list_audit_logs_filter_action(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_log(user_id, action="LOGIN")
    create_log(user_id, action="LOGOUT")

    response = client.get(
        "/audit-logs/",
        params={"action": "LOGIN"},
    )

    assert response.status_code == 200, response.text
    assert all(item["action"] == "LOGIN" for item in response.json())


def test_list_audit_logs_filter_resource_type(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_log(user_id, resource_type="asset")
    create_log(user_id, resource_type="user")

    response = client.get(
        "/audit-logs/",
        params={"resource_type": "asset"},
    )

    assert response.status_code == 200, response.text
    assert all(
        item["resource_type"] == "asset"
        for item in response.json()
    )


def test_list_audit_logs_date_range(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_log(user_id)

    now = datetime.now(timezone.utc)
    response = client.get(
        "/audit-logs/",
        params={
            "start_date": (now - timedelta(days=1)).isoformat(),
            "end_date": (now + timedelta(days=1)).isoformat(),
        },
    )

    assert response.status_code == 200, response.text
    assert len(response.json()) >= 1


def test_list_audit_logs_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    for index in range(3):
        create_log(user_id, action=f"ACTION_{index}")

    response = client.get(
        "/audit-logs/",
        params={"skip": 0, "limit": 2},
    )

    assert response.status_code == 200, response.text
    assert len(response.json()) <= 2


def test_list_audit_logs_invalid_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get(
        "/audit-logs/",
        params={"skip": -1},
    )
    assert response.status_code == 422

    response = client.get(
        "/audit-logs/",
        params={"limit": 0},
    )
    assert response.status_code == 422

    response = client.get(
        "/audit-logs/",
        params={"limit": 501},
    )
    assert response.status_code == 422


def test_list_audit_logs_forbidden(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_ANALYST)

    response = client.get("/audit-logs/")

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


def test_get_audit_log_success(client):
    user_id = register_user(client)
    set_actor(user_id)

    log_id = create_log(user_id)

    response = client.get(f"/audit-logs/{log_id}")

    assert response.status_code == 200, response.text
    assert response.json()["id"] == log_id
    assert response.json()["action"] == "LOGIN"


def test_get_audit_log_not_found(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/audit-logs/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Audit log not found"


def test_get_audit_log_forbidden(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_ANALYST)

    response = client.get("/audit-logs/1")

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"
