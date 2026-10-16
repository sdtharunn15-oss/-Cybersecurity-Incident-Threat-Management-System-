from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import Boolean, DateTime, Enum as SAEnum, Integer, String, Text

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import User
from app.models.incident import SecurityIncident
from app.models.sla import (
    IncidentSLAPolicy,
    IncidentSLA,
    SLAHistory,
    SLAPriority,
    SLAStatus,
)


def get_test_db():
    generator = app.dependency_overrides[get_db]()
    db = next(generator)
    return db, generator



def create_test_user(db, role="security_manager"):
    """Create a database user with the requested role."""
    values = {}
    unique = uuid4().hex

    for column in User.__table__.columns:
        name = column.name

        # Handle role before skipping columns with defaults.
        if name == "role":
            enum_type = getattr(column.type, "enum_class", None)

            if enum_type:
                matching_role = next(
                    (
                        item
                        for item in enum_type
                        if item.value == role
                        or item.name.lower() == role.lower()
                    ),
                    None,
                )

                if matching_role is None:
                    raise ValueError(f"Invalid user role: {role}")

                values[name] = matching_role
            else:
                values[name] = role

            continue

        if name == "id" or column.nullable or column.default is not None:
            continue

        if isinstance(column.type, SAEnum):
            values[name] = next(iter(column.type.enum_class))

        elif isinstance(column.type, Boolean):
            values[name] = True

        elif isinstance(column.type, DateTime):
            values[name] = datetime.utcnow()

        elif isinstance(column.type, Integer):
            values[name] = 1

        elif isinstance(column.type, (String, Text)):
            if "email" in name:
                values[name] = f"{unique}@example.com"
            elif "username" in name:
                values[name] = f"user_{unique}"
            elif "password" in name:
                values[name] = f"TestPassword_{unique}"
            else:
                values[name] = f"test_{unique}"

    user = User(**values)
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def set_actor(user):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user.id,
        role=(
            user.role.value
            if hasattr(user.role, "value")
            else user.role
        ),
    )


def create_incident(db, user):
    incident = SecurityIncident(
        incident_number=f"INC-{uuid4().hex[:12].upper()}",
        title="Test security incident",
        description="Incident created for SLA tests",
        created_by_id=user.id,
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


def create_policy(db, priority=SLAPriority.HIGH, active=True):
    policy = IncidentSLAPolicy(
        name=f"Test policy {uuid4().hex[:8]}",
        priority=priority,
        response_minutes=30,
        resolution_minutes=120,
        description="Test SLA policy",
        is_active=active,
    )

    db.add(policy)
    db.commit()
    db.refresh(policy)

    return policy


def setup_records(client, role="security_manager", with_policy=True):
    db, generator = get_test_db()

    try:
        user = create_test_user(db, role)
        incident = create_incident(db, user)
        policy = create_policy(db) if with_policy else None

        set_actor(user)

        return db, generator, user, incident, policy

    except Exception:
        db.close()
        generator.close()
        raise


@pytest.fixture(autouse=True)
def clear_actor_override():
    app.dependency_overrides.pop(get_current_user, None)

    yield

    app.dependency_overrides.pop(get_current_user, None)


def test_list_policies_empty(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.get("/sla/policies")

        assert response.status_code == 200
        assert response.json() == []

    finally:
        db.close()
        generator.close()


def test_create_policy(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.post(
            "/sla/policies",
            json={
                "name": "High priority policy",
                "priority": "high",
                "response_minutes": 30,
                "resolution_minutes": 120,
                "description": "Test policy",
            },
        )

        assert response.status_code == 201, response.text

        data = response.json()

        assert data["name"] == "High priority policy"
        assert data["priority"] == "high"
        assert data["response_minutes"] == 30
        assert data["resolution_minutes"] == 120

    finally:
        db.close()
        generator.close()


def test_create_policy_duplicate_priority_returns_conflict(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))
        create_policy(db, SLAPriority.HIGH)

        response = client.post(
            "/sla/policies",
            json={
                "name": "Duplicate high policy",
                "priority": "high",
                "response_minutes": 20,
                "resolution_minutes": 90,
            },
        )

        assert response.status_code == 409, response.text

    finally:
        db.close()
        generator.close()


@pytest.mark.parametrize(
    "payload",
    [
        {
            "name": "",
            "priority": "high",
            "response_minutes": 30,
            "resolution_minutes": 120,
        },
        {
            "name": "Invalid response time",
            "priority": "high",
            "response_minutes": 0,
            "resolution_minutes": 120,
        },
        {
            "name": "Invalid resolution time",
            "priority": "high",
            "response_minutes": 30,
            "resolution_minutes": -1,
        },
        {
            "name": "Invalid priority",
            "priority": "urgent",
            "response_minutes": 30,
            "resolution_minutes": 120,
        },
    ],
)
def test_create_policy_invalid_payload(client, payload):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.post("/sla/policies", json=payload)

        assert response.status_code == 422

    finally:
        db.close()
        generator.close()


def test_create_policy_forbidden_for_analyst(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db, "security_analyst"))

        response = client.post(
            "/sla/policies",
            json={
                "name": "Analyst policy",
                "priority": "medium",
                "response_minutes": 30,
                "resolution_minutes": 120,
            },
        )

        assert response.status_code == 403

    finally:
        db.close()
        generator.close()


def test_list_policies(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        create_policy(db, SLAPriority.HIGH)
        create_policy(db, SLAPriority.LOW)

        response = client.get("/sla/policies")

        assert response.status_code == 200
        assert len(response.json()) == 2

    finally:
        db.close()
        generator.close()


def test_assign_sla(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        response = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert response.status_code in (200, 201), response.text

        data = response.json()

        assert data["incident_id"] == incident.id
        assert data["policy_id"] == policy.id
        assert data["status"] == "active"
        assert data["response_breached"] is False
        assert data["resolution_breached"] is False

        history = (
            db.query(SLAHistory)
            .filter_by(sla_id=data["id"])
            .all()
        )

        assert len(history) >= 1

    finally:
        db.close()
        generator.close()


def test_assign_sla_missing_incident(client):
    db, generator = get_test_db()

    try:
        user = create_test_user(db)
        policy = create_policy(db)
        set_actor(user)

        response = client.post(
            "/sla/assign",
            json={
                "incident_id": 999999,
                "policy_id": policy.id,
            },
        )

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()


def test_assign_sla_missing_policy(client):
    db, generator = get_test_db()

    try:
        user = create_test_user(db)
        incident = create_incident(db, user)
        set_actor(user)

        response = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": 999999,
            },
        )

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()


def test_assign_sla_duplicate_incident(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        first = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert first.status_code in (200, 201), first.text

        second = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert second.status_code == 409

    finally:
        db.close()
        generator.close()


def test_assign_sla_forbidden_for_analyst(client):
    db, generator = get_test_db()

    try:
        user = create_test_user(db, "security_analyst")
        incident = create_incident(db, user)
        policy = create_policy(db)

        set_actor(user)

        response = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert response.status_code == 403

    finally:
        db.close()
        generator.close()


def test_list_slas_and_filter_by_status(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        all_response = client.get("/sla/")

        assert all_response.status_code == 200
        assert len(all_response.json()) == 1

        active_response = client.get(
            "/sla/",
            params={"status_filter": "active"},
        )

        assert active_response.status_code == 200
        assert len(active_response.json()) == 1

        met_response = client.get(
            "/sla/",
            params={"status_filter": "met"},
        )

        assert met_response.status_code == 200
        assert met_response.json() == []

    finally:
        db.close()
        generator.close()


def test_list_breached_slas(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        db_sla = db.query(IncidentSLA).filter_by(id=sla_id).first()

        assert db_sla is not None

        db_sla.status = SLAStatus.BREACHED
        db.commit()

        response = client.get("/sla/breached")

        assert response.status_code == 200
        assert any(
            item["id"] == sla_id
            for item in response.json()
        )

    finally:
        db.close()
        generator.close()


def test_get_sla_by_id(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        response = client.get(f"/sla/{sla_id}")

        assert response.status_code == 200
        assert response.json()["id"] == sla_id

    finally:
        db.close()
        generator.close()


def test_get_missing_sla_returns_404(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.get("/sla/999999")

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()


def test_respond_to_sla(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        response = client.patch(
            f"/sla/{sla_id}/respond",
            json={"notes": "Initial response sent"},
        )

        assert response.status_code == 200, response.text

        data = response.json()

        assert data["first_responded_at"] is not None
        assert data["notes"] == "Initial response sent"

    finally:
        db.close()
        generator.close()


def test_respond_to_sla_twice_returns_conflict(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        first = client.patch(
            f"/sla/{sla_id}/respond",
            json={"notes": "First response"},
        )

        assert first.status_code == 200, first.text

        second = client.patch(
            f"/sla/{sla_id}/respond",
            json={"notes": "Second response"},
        )

        assert second.status_code == 409

    finally:
        db.close()
        generator.close()


def test_respond_to_missing_sla_returns_404(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.patch(
            "/sla/999999/respond",
            json={"notes": "Response"},
        )

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()


def test_resolve_sla(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        response = client.patch(
            f"/sla/{sla_id}/resolve",
            json={"notes": "Issue resolved"},
        )

        assert response.status_code == 200, response.text

        data = response.json()

        assert data["resolved_at"] is not None
        assert data["notes"] == "Issue resolved"
        assert data["status"] in ("met", "breached")

    finally:
        db.close()
        generator.close()


def test_resolve_missing_sla_returns_404(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.patch(
            "/sla/999999/resolve",
            json={"notes": "Resolved"},
        )

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()


def test_update_sla_status(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        response = client.patch(
            f"/sla/{sla_id}/status",
            json={
                "status": "paused",
                "notes": "Waiting for approval",
            },
        )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "paused"
        assert response.json()["notes"] == "Waiting for approval"

    finally:
        db.close()
        generator.close()


def test_update_missing_sla_status_returns_404(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.patch(
            "/sla/999999/status",
            json={
                "status": "paused",
                "notes": "Pause",
            },
        )

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()


def test_update_sla_status_invalid_value(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        response = client.patch(
            f"/sla/{sla_id}/status",
            json={
                "status": "unknown",
                "notes": "Invalid",
            },
        )

        assert response.status_code == 422

    finally:
        db.close()
        generator.close()


def test_get_sla_history(client):
    db, generator, user, incident, policy = setup_records(client)

    try:
        assigned = client.post(
            "/sla/assign",
            json={
                "incident_id": incident.id,
                "policy_id": policy.id,
            },
        )

        assert assigned.status_code in (200, 201), assigned.text

        sla_id = assigned.json()["id"]

        response_to_sla = client.patch(
            f"/sla/{sla_id}/respond",
            json={"notes": "Response recorded"},
        )

        assert response_to_sla.status_code == 200, response_to_sla.text

        response = client.get(f"/sla/{sla_id}/history")

        assert response.status_code == 200
        assert len(response.json()) >= 2

    finally:
        db.close()
        generator.close()


def test_get_history_for_missing_sla_returns_404(client):
    db, generator = get_test_db()

    try:
        set_actor(create_test_user(db))

        response = client.get("/sla/999999/history")

        assert response.status_code == 404

    finally:
        db.close()
        generator.close()