
from types import SimpleNamespace

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import User, UserRole
from app.models.incident import (
    SecurityIncident,
    IncidentSeverity,
    IncidentStatus,
    IncidentStatusHistory,
)
from app.models.organization import (
    Organization,
    Department,
    Asset,
    AssetType,
    AssetCriticality,
    AssetStatus,
)


def register_user(client, email="incident-user@example.com"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Incident Test User",
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SECURITY_ANALYST, is_active=True):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
        is_active=is_active,
    )


def get_test_db():
    db_dependency = app.dependency_overrides[get_db]
    return next(db_dependency())


def set_user_role(user_id, role, is_active=True):
    db = get_test_db()
    try:
        user = db.get(User, user_id)
        user.role = role
        user.is_active = is_active
        db.commit()
    finally:
        db.close()


def create_incident(client, title="Test security incident", **overrides):
    payload = {
        "title": title,
        "description": "A security event requiring investigation.",
        "severity": "medium",
    }
    payload.update(overrides)
    response = client.post("/incidents", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def set_incident_fields(incident_id, **fields):
    db = get_test_db()
    try:
        incident = db.get(SecurityIncident, incident_id)
        for field, value in fields.items():
            setattr(incident, field, value)
        db.commit()
    finally:
        db.close()


def create_asset():
    db = get_test_db()
    try:
        organization = Organization(
            name="Incident Test Organization",
            description="Test organization",
        )
        db.add(organization)
        db.flush()

        department = Department(
            name="Security",
            organization_id=organization.id,
        )
        db.add(department)
        db.flush()

        asset = Asset(
            name="Test Server",
            asset_tag="INCIDENT-ASSET-001",
            asset_type=AssetType.SERVER,
            criticality=AssetCriticality.HIGH,
            status=AssetStatus.ACTIVE,
            organization_id=organization.id,
            department_id=department.id,
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return asset.id
    finally:
        db.close()


def test_create_incident_success(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/incidents",
        json={
            "title": "Suspicious login activity",
            "description": "Multiple suspicious login attempts detected.",
            "severity": "high",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Suspicious login activity"
    assert data["severity"] == "high"
    assert data["status"] == "new"
    assert data["created_by_id"] == user_id
    assert data["incident_number"].startswith("INC-")
    assert data["alert_ids"] == []


def test_create_incident_invalid_title(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/incidents",
        json={
            "title": "ab",
            "description": "A valid description for testing.",
        },
    )

    assert response.status_code == 422


def test_create_incident_inactive_user_forbidden(client):
    user_id = register_user(client)
    set_actor(user_id, is_active=False)

    response = client.post(
        "/incidents",
        json={
            "title": "Inactive user incident",
            "description": "This request should be forbidden.",
        },
    )

    assert response.status_code == 403


def test_create_incident_unsupported_role_forbidden(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.AUDITOR)

    response = client.post(
        "/incidents",
        json={
            "title": "Auditor incident",
            "description": "This request should be forbidden.",
        },
    )

    assert response.status_code == 403


def test_create_incident_with_missing_asset_returns_404(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/incidents",
        json={
            "title": "Missing asset incident",
            "description": "The affected asset does not exist.",
            "affected_asset_id": 99999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Affected asset not found."


def test_create_incident_with_decommissioned_asset_returns_400(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    db = get_test_db()
    try:
        asset = db.get(Asset, asset_id)
        asset.status = AssetStatus.DECOMMISSIONED
        db.commit()
    finally:
        db.close()

    response = client.post(
        "/incidents",
        json={
            "title": "Decommissioned asset incident",
            "description": "This asset cannot be linked to a new incident.",
            "affected_asset_id": asset_id,
        },
    )

    assert response.status_code == 400
    assert "decommissioned asset" in response.json()["detail"]


def test_create_incident_with_valid_asset(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    incident = create_incident(
        client,
        affected_asset_id=asset_id,
    )

    assert incident["affected_asset_id"] == asset_id


def test_create_incident_with_invalid_assignee_returns_400(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/incidents",
        json={
            "title": "Invalid assignee incident",
            "description": "The assignee does not exist.",
            "assigned_to_id": 99999,
        },
    )

    assert response.status_code == 400
    assert "active Security Analyst" in response.json()["detail"]


def test_list_incidents_and_search(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_incident(client, title="Firewall intrusion")
    create_incident(client, title="Email phishing attempt")

    response = client.get("/incidents")
    assert response.status_code == 200
    assert len(response.json()) == 2

    response = client.get("/incidents", params={"q": "firewall"})
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["title"] == "Firewall intrusion"


def test_list_incidents_filter_by_severity(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_incident(client, title="Low severity", severity="low")
    create_incident(client, title="Critical severity", severity="critical")

    response = client.get("/incidents", params={"severity": "critical"})

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["severity"] == "critical"


def test_list_incidents_filter_by_status(client):
    user_id = register_user(client)
    set_actor(user_id)

    first = create_incident(client, title="New incident")
    second = create_incident(client, title="Triaged incident")
    set_incident_fields(second["id"], status=IncidentStatus.TRIAGED)

    response = client.get("/incidents", params={"status": "triaged"})

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [second["id"]]


def test_list_incidents_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    for index in range(3):
        create_incident(client, title=f"Pagination incident {index}")

    response = client.get(
        "/incidents",
        params={"page": 1, "page_size": 2},
    )

    assert response.status_code == 200
    assert len(response.json()) == 2

    response = client.get(
        "/incidents",
        params={"page": 0, "page_size": 2},
    )
    assert response.status_code == 422


def test_assigned_to_me(client):
    user_id = register_user(client)
    set_actor(user_id)

    incident = create_incident(client)
    set_incident_fields(incident["id"], assigned_to_id=user_id)

    response = client.get("/incidents/assigned-to-me")

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == incident["id"]


def test_get_incident_not_found(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/incidents/99999")

    assert response.status_code == 404


def test_update_incident_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.patch(
        f"/incidents/{incident['id']}",
        json={"title": "Updated incident title", "severity": "high"},
    )

    assert response.status_code == 200
    assert response.json()["title"] == "Updated incident title"
    assert response.json()["severity"] == "high"


def test_update_incident_forbidden_for_unrelated_analyst(client):
    owner_id = register_user(client, "owner@example.com")
    incident = create_incident(client) if False else None

    set_actor(owner_id)
    incident = create_incident(client)

    other_id = register_user(client, "other@example.com")
    set_actor(other_id)

    response = client.patch(
        f"/incidents/{incident['id']}",
        json={"title": "Unauthorized change"},
    )

    assert response.status_code == 403


def test_update_closed_incident_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)
    set_incident_fields(incident["id"], status=IncidentStatus.CLOSED)

    response = client.patch(
        f"/incidents/{incident['id']}",
        json={"title": "Cannot update closed incident"},
    )

    assert response.status_code == 400


def test_add_and_list_investigation_notes(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.post(
        f"/incidents/{incident['id']}/notes",
        json={"note": "Reviewed the authentication logs."},
    )

    assert response.status_code == 201
    assert response.json()["note"] == "Reviewed the authentication logs."

    response = client.get(f"/incidents/{incident['id']}/notes")

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_add_note_to_closed_incident_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)
    set_incident_fields(incident["id"], status=IncidentStatus.CLOSED)

    response = client.post(
        f"/incidents/{incident['id']}/notes",
        json={"note": "Attempted note"},
    )

    assert response.status_code == 400


def test_update_incident_status_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.patch(
        f"/incidents/{incident['id']}/status",
        json={"status": "triaged", "reason": "Initial review completed."},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "triaged"


def test_invalid_status_transition_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.patch(
        f"/incidents/{incident['id']}/status",
        json={"status": "resolved"},
    )

    assert response.status_code == 400
    assert "Invalid status transition" in response.json()["detail"]


def test_repeating_current_status_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.patch(
        f"/incidents/{incident['id']}/status",
        json={"status": "new"},
    )

    assert response.status_code == 400
    assert "already has this status" in response.json()["detail"]


def test_analyst_cannot_close_incident(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.patch(
        f"/incidents/{incident['id']}/status",
        json={"status": "closed"},
    )

    assert response.status_code == 403


def test_resolve_incident_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)
    set_incident_fields(
        incident["id"],
        status=IncidentStatus.INVESTIGATING,
    )

    response = client.patch(
        f"/incidents/{incident['id']}/resolve",
        json={"resolution_summary": "Malicious activity contained."},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"
    assert response.json()["resolution_summary"] == "Malicious activity contained."
    assert response.json()["resolved_at"] is not None


def test_resolve_incident_invalid_status_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.patch(
        f"/incidents/{incident['id']}/resolve",
        json={"resolution_summary": "Incident resolved successfully."},
    )

    assert response.status_code == 400


def test_incident_history(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.get(f"/incidents/{incident['id']}/history")

    assert response.status_code == 200
    history = response.json()
    assert len(history) >= 1
    assert history[0]["new_status"] == "new"


def test_incident_history_not_found(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/incidents/99999/history")

    assert response.status_code == 404
