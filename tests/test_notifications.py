
from uuid import uuid4

import pytest

from app.api.auth.routes import get_current_user
from app.db.database import get_db
from app.main import app
from app.models.notification import Notification, NotificationType
from app.models.user import User, UserRole


def register_user(client, email_prefix="notification"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Notification Test User",
            "email": f"{email_prefix}_{uuid4().hex[:10]}@example.com",
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SECURITY_ANALYST):
    app.dependency_overrides[get_current_user] = lambda: type(
        "TestUser",
        (),
        {"id": user_id, "role": role, "is_active": True},
    )()


def get_test_db():
    db_generator = app.dependency_overrides[get_db]()
    return next(db_generator)


def create_notification(
    db,
    recipient_id,
    sender_id=None,
    title="Test notification",
    is_read=False,
):
    notification = Notification(
        recipient_id=recipient_id,
        sender_id=sender_id,
        notification_type=NotificationType.GENERAL,
        title=title,
        message="Notification test message",
        is_read=is_read,
    )
    db.add(notification)
    db.commit()
    db.refresh(notification)
    return notification


@pytest.fixture(autouse=True)
def clear_actor_override():
    app.dependency_overrides.pop(get_current_user, None)
    yield
    app.dependency_overrides.pop(get_current_user, None)


def test_create_notification_success(client):
    recipient_id = register_user(client, "recipient")
    sender_id = register_user(client, "sender")
    set_actor(sender_id, UserRole.SUPER_ADMIN)

    response = client.post(
        "/notifications/",
        json={
            "recipient_id": recipient_id,
            "notification_type": "security_alert",
            "title": "Security warning",
            "message": "Suspicious activity detected",
            "resource_type": "incident",
            "resource_id": "INC-100",
        },
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["recipient_id"] == recipient_id
    assert data["sender_id"] == sender_id
    assert data["notification_type"] == "security_alert"
    assert data["title"] == "Security warning"
    assert data["message"] == "Suspicious activity detected"
    assert data["resource_type"] == "incident"
    assert data["resource_id"] == "INC-100"
    assert data["is_read"] is False
    assert data["read_at"] is None


def test_create_notification_forbidden_for_analyst(client):
    recipient_id = register_user(client, "recipient")
    sender_id = register_user(client, "sender")
    set_actor(sender_id, UserRole.SECURITY_ANALYST)

    response = client.post(
        "/notifications/",
        json={
            "recipient_id": recipient_id,
            "title": "Restricted",
            "message": "This should be rejected",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Insufficient permissions to send notifications"
    )


def test_create_notification_forbidden_for_auditor(client):
    recipient_id = register_user(client, "recipient")
    sender_id = register_user(client, "sender")
    set_actor(sender_id, UserRole.AUDITOR)

    response = client.post(
        "/notifications/",
        json={
            "recipient_id": recipient_id,
            "title": "Restricted",
            "message": "This should be rejected",
        },
    )

    assert response.status_code == 403


def test_create_notification_recipient_not_found(client):
    sender_id = register_user(client, "sender")
    set_actor(sender_id, UserRole.SECURITY_MANAGER)

    response = client.post(
        "/notifications/",
        json={
            "recipient_id": 999999,
            "title": "Missing recipient",
            "message": "Recipient does not exist",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Recipient user not found"


def test_create_notification_invalid_payload(client):
    sender_id = register_user(client, "sender")
    set_actor(sender_id, UserRole.SUPER_ADMIN)

    response = client.post(
        "/notifications/",
        json={
            "recipient_id": sender_id,
            "title": "",
            "message": "Invalid title",
        },
    )

    assert response.status_code == 422


def test_unread_count(client):
    user_id = register_user(client, "unread")
    set_actor(user_id)

    db = get_test_db()
    try:
        create_notification(db, user_id, title="Unread one")
        create_notification(db, user_id, title="Unread two")
        create_notification(
            db, user_id, title="Read one", is_read=True
        )
    finally:
        db.close()

    response = client.get("/notifications/unread-count")

    assert response.status_code == 200
    assert response.json() == {"unread_count": 2}


def test_list_my_notifications(client):
    user_id = register_user(client, "list")
    other_user_id = register_user(client, "other")
    set_actor(user_id)

    db = get_test_db()
    try:
        create_notification(db, user_id, title="First")
        create_notification(db, user_id, title="Second")
        create_notification(db, other_user_id, title="Other user's item")
    finally:
        db.close()

    response = client.get("/notifications/")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert all(item["recipient_id"] == user_id for item in data)


def test_list_notifications_unread_only(client):
    user_id = register_user(client, "unreadlist")
    set_actor(user_id)

    db = get_test_db()
    try:
        create_notification(db, user_id, title="Unread")
        create_notification(
            db, user_id, title="Already read", is_read=True
        )
    finally:
        db.close()

    response = client.get("/notifications/?unread_only=true")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Unread"
    assert data[0]["is_read"] is False


def test_list_notifications_pagination(client):
    user_id = register_user(client, "pagination")
    set_actor(user_id)

    db = get_test_db()
    try:
        for number in range(4):
            create_notification(
                db, user_id, title=f"Notification {number}"
            )
    finally:
        db.close()

    response = client.get("/notifications/?skip=1&limit=2")

    assert response.status_code == 200
    assert len(response.json()) == 2


@pytest.mark.parametrize(
    "query",
    [
        "?skip=-1",
        "?limit=0",
        "?limit=201",
    ],
)
def test_list_notifications_invalid_pagination(client, query):
    user_id = register_user(client, "invalidpagination")
    set_actor(user_id)

    response = client.get(f"/notifications/{query}")

    assert response.status_code == 422


def test_get_notification_success(client):
    user_id = register_user(client, "get")
    set_actor(user_id)

    db = get_test_db()
    try:
        notification = create_notification(
            db, user_id, title="Requested notification"
        )
        notification_id = notification.id
    finally:
        db.close()

    response = client.get(f"/notifications/{notification_id}")

    assert response.status_code == 200
    assert response.json()["title"] == "Requested notification"


def test_get_notification_not_found(client):
    user_id = register_user(client, "missing")
    set_actor(user_id)

    response = client.get("/notifications/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Notification not found"


def test_user_cannot_get_another_users_notification(client):
    owner_id = register_user(client, "owner")
    other_id = register_user(client, "viewer")
    set_actor(other_id)

    db = get_test_db()
    try:
        notification = create_notification(
            db, owner_id, title="Private notification"
        )
        notification_id = notification.id
    finally:
        db.close()

    response = client.get(f"/notifications/{notification_id}")

    assert response.status_code == 404


def test_mark_notification_as_read(client):
    user_id = register_user(client, "markread")
    set_actor(user_id)

    db = get_test_db()
    try:
        notification = create_notification(
            db, user_id, title="Mark me read"
        )
        notification_id = notification.id
    finally:
        db.close()

    response = client.patch(
        f"/notifications/{notification_id}/read"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_read"] is True
    assert data["read_at"] is not None


def test_mark_already_read_notification(client):
    user_id = register_user(client, "alreadyread")
    set_actor(user_id)

    db = get_test_db()
    try:
        notification = create_notification(
            db, user_id, title="Already read", is_read=True
        )
        notification_id = notification.id
    finally:
        db.close()

    response = client.patch(
        f"/notifications/{notification_id}/read"
    )

    assert response.status_code == 200
    assert response.json()["is_read"] is True


def test_mark_notification_read_not_found(client):
    user_id = register_user(client, "readmissing")
    set_actor(user_id)

    response = client.patch("/notifications/999999/read")

    assert response.status_code == 404


def test_mark_all_notifications_as_read(client):
    user_id = register_user(client, "markall")
    set_actor(user_id)

    db = get_test_db()
    try:
        create_notification(db, user_id, title="Unread one")
        create_notification(db, user_id, title="Unread two")
        create_notification(
            db, user_id, title="Already read", is_read=True
        )
    finally:
        db.close()

    response = client.patch("/notifications/read-all")

    assert response.status_code == 200
    assert response.json()["updated_count"] == 2

    db = get_test_db()
    try:
        unread_count = (
            db.query(Notification)
            .filter(
                Notification.recipient_id == user_id,
                Notification.is_read.is_(False),
            )
            .count()
        )
    finally:
        db.close()

    assert unread_count == 0


def test_mark_all_notifications_when_none_unread(client):
    user_id = register_user(client, "noneunread")
    set_actor(user_id)

    db = get_test_db()
    try:
        create_notification(
            db, user_id, title="Already read", is_read=True
        )
    finally:
        db.close()

    response = client.patch("/notifications/read-all")

    assert response.status_code == 200
    assert response.json()["updated_count"] == 0
