
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.incident import (
    SecurityIncident,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.investigation import (
    Investigation,
    InvestigationNote,
    InvestigationEvidence,
    InvestigationHistory,
    InvestigationStatus,
    InvestigationPriority,
)


def register_user(client, email=None):
    email = email or f"investigator-{uuid4().hex[:8]}@example.com"
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Investigation Test User",
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SECURITY_ANALYST):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
    )


def get_test_db():
    db_dependency = app.dependency_overrides[get_db]
    return next(db_dependency())


def create_incident(user_id):
    db = get_test_db()
    try:
        incident = SecurityIncident(
            incident_number=f"INC-{uuid4().hex[:10].upper()}",
            title="Suspicious server activity",
            description="Unexpected outbound network activity detected.",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.INVESTIGATING,
            created_by_id=user_id,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.id
    finally:
        db.close()


def create_investigation(client, user_id, incident_id=None, **overrides):
    incident_id = incident_id or create_incident(user_id)
    payload = {
        "title": "Investigate suspicious activity",
        "objective": "Determine the cause of unusual network traffic.",
        "incident_id": incident_id,
        "priority": "high",
    }
    payload.update(overrides)
    set_actor(user_id)
    response = client.post("/investigations/", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_create_investigation_without_assignee(client):
    user_id = register_user(client)
    incident_id = create_incident(user_id)
    set_actor(user_id)

    response = client.post(
        "/investigations/",
        json={
            "title": "Investigate incident",
            "objective": "Identify the source of the incident.",
            "incident_id": incident_id,
            "priority": "high",
        },
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["incident_id"] == incident_id
    assert data["created_by_id"] == user_id
    assert data["status"] == "open"
    assert data["assigned_to_id"] is None
    assert data["started_at"] is None
    assert data["investigation_number"].startswith("INV-")


def test_create_investigation_with_assignee(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    incident_id = create_incident(user_id)
    set_actor(user_id)

    response = client.post(
        "/investigations/",
        json={
            "title": "Assigned investigation",
            "objective": "Determine the scope of the security event.",
            "incident_id": incident_id,
            "assigned_to_id": assignee_id,
        },
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["assigned_to_id"] == assignee_id
    assert data["status"] == "in_progress"
    assert data["started_at"] is not None


def test_create_investigation_missing_incident(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/investigations/",
        json={
            "title": "Missing incident",
            "objective": "Investigate an unavailable incident.",
            "incident_id": 999999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


def test_create_investigation_missing_assignee(client):
    user_id = register_user(client)
    incident_id = create_incident(user_id)
    set_actor(user_id)

    response = client.post(
        "/investigations/",
        json={
            "title": "Missing assignee",
            "objective": "Investigate an incident with an invalid assignee.",
            "incident_id": incident_id,
            "assigned_to_id": 999999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Assignee not found"


def test_create_investigation_validation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/investigations/",
        json={
            "title": "AB",
            "objective": "Short",
            "incident_id": 0,
        },
    )

    assert response.status_code == 422


def test_list_investigations_and_filters(client):
    user_id = register_user(client)
    incident_id = create_incident(user_id)

    first = create_investigation(
        client,
        user_id,
        incident_id,
        title="Network investigation alpha",
        priority="high",
    )
    second = create_investigation(
        client,
        user_id,
        incident_id,
        title="Endpoint investigation beta",
        priority="low",
    )

    response = client.get("/investigations/")
    assert response.status_code == 200, response.text
    assert len(response.json()) == 2

    response = client.get("/investigations/?priority=high")
    assert response.status_code == 200
    assert all(item["priority"] == "high" for item in response.json())
    assert len(response.json()) == 1

    response = client.get(f"/investigations/?incident_id={incident_id}")
    assert response.status_code == 200
    assert len(response.json()) == 2

    response = client.get(
        f"/investigations/?q={first['title'].split()[0]}"
    )
    assert response.status_code == 200
    assert any(item["id"] == first["id"] for item in response.json())

    response = client.get("/investigations/?skip=1&limit=1")
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = client.get("/investigations/?limit=0")
    assert response.status_code == 422

    response = client.get("/investigations/?incident_id=0")
    assert response.status_code == 422


def test_list_investigations_by_status(client):
    user_id = register_user(client)
    create_investigation(client, user_id)

    response = client.get("/investigations/?status=open")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["status"] == "open"


def test_assigned_to_me(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    incident_id = create_incident(user_id)

    create_investigation(
        client,
        user_id,
        incident_id,
        assigned_to_id=assignee_id,
    )
    set_actor(assignee_id)

    response = client.get("/investigations/assigned-to-me")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["assigned_to_id"] == assignee_id


def test_get_investigation_and_missing_id(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)

    response = client.get(f"/investigations/{investigation['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == investigation["id"]

    response = client.get("/investigations/999999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Investigation not found"


def test_update_investigation_and_history(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.patch(
        f"/investigations/{investigation['id']}",
        json={
            "title": "Updated investigation title",
            "findings": "Suspicious process identified.",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["title"] == "Updated investigation title"
    assert response.json()["findings"] == "Suspicious process identified."

    response = client.get(
        f"/investigations/{investigation['id']}/history"
    )
    assert response.status_code == 200
    assert any(
        entry["action"] == "title_updated"
        for entry in response.json()
    )


def test_update_same_values_does_not_add_history(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.patch(
        f"/investigations/{investigation['id']}",
        json={"title": investigation["title"]},
    )
    assert response.status_code == 200, response.text

    history_response = client.get(
        f"/investigations/{investigation['id']}/history"
    )
    actions = [entry["action"] for entry in history_response.json()]
    assert "title_updated" not in actions


def test_update_missing_investigation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/investigations/999999",
        json={"title": "Updated investigation"},
    )

    assert response.status_code == 404


def test_closed_investigation_cannot_be_updated(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)

    db = get_test_db()
    try:
        item = db.query(Investigation).filter_by(
            id=investigation["id"]
        ).first()
        item.status = InvestigationStatus.CLOSED
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/investigations/{investigation['id']}",
        json={"title": "Should not update"},
    )

    assert response.status_code == 400


def test_assign_investigation(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.patch(
        f"/investigations/{investigation['id']}/assign",
        json={
            "assigned_to_id": assignee_id,
            "reason": "Assign to investigation analyst",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["assigned_to_id"] == assignee_id
    assert response.json()["status"] == "in_progress"
    assert response.json()["started_at"] is not None


def test_assign_missing_assignee(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.patch(
        f"/investigations/{investigation['id']}/assign",
        json={
            "assigned_to_id": 999999,
            "reason": "Invalid assignee",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Assignee not found"


def test_closed_investigation_cannot_be_assigned(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    investigation = create_investigation(client, user_id)

    db = get_test_db()
    try:
        item = db.query(Investigation).filter_by(
            id=investigation["id"]
        ).first()
        item.status = InvestigationStatus.CLOSED
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/investigations/{investigation['id']}/assign",
        json={
            "assigned_to_id": assignee_id,
            "reason": "Try to reassign closed investigation",
        },
    )

    assert response.status_code == 400


def test_add_and_list_investigation_notes(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.post(
        f"/investigations/{investigation['id']}/notes",
        json={"note": "Reviewed the suspicious login activity."},
    )

    assert response.status_code == 201, response.text
    assert response.json()["author_id"] == user_id

    response = client.get(
        f"/investigations/{investigation['id']}/notes"
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["note"] == (
        "Reviewed the suspicious login activity."
    )


def test_cannot_add_note_to_closed_investigation(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)

    db = get_test_db()
    try:
        item = db.query(Investigation).filter_by(
            id=investigation["id"]
        ).first()
        item.status = InvestigationStatus.CLOSED
        db.commit()
    finally:
        db.close()

    response = client.post(
        f"/investigations/{investigation['id']}/notes",
        json={"note": "Late note"},
    )

    assert response.status_code == 400


def test_notes_for_missing_investigation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/investigations/999999/notes")

    assert response.status_code == 404


def test_add_and_list_evidence(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.post(
        f"/investigations/{investigation['id']}/evidence",
        json={
            "evidence_type": "log_file",
            "reference": "evidence/server-logs.txt",
            "description": "Relevant server log excerpt",
            "integrity_hash": "a" * 64,
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["submitted_by_id"] == user_id

    response = client.get(
        f"/investigations/{investigation['id']}/evidence"
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["reference"] == "evidence/server-logs.txt"


def test_cannot_add_evidence_to_closed_investigation(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)

    db = get_test_db()
    try:
        item = db.query(Investigation).filter_by(
            id=investigation["id"]
        ).first()
        item.status = InvestigationStatus.CLOSED
        db.commit()
    finally:
        db.close()

    response = client.post(
        f"/investigations/{investigation['id']}/evidence",
        json={
            "evidence_type": "log_file",
            "reference": "evidence/late.txt",
        },
    )

    assert response.status_code == 400


def test_evidence_for_missing_investigation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/investigations/999999/evidence")

    assert response.status_code == 404



def test_analyst_cannot_submit_for_review(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id, UserRole.SECURITY_ANALYST)

    # Move to in_progress first, using the allowed transition.
    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "in_progress",
            "reason": "Start investigation",
        },
    )
    assert response.status_code == 200, response.text

    # Analysts should not be allowed to submit for review.
    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "pending_review",
            "reason": "Submit findings for manager review",
        },
    )

    assert response.status_code == 403



def test_manager_can_submit_for_review(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id, UserRole.SECURITY_MANAGER)

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "in_progress",
            "reason": "Start investigation",
        },
    )
    assert response.status_code == 200, response.text

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "pending_review",
            "reason": "Investigation findings are ready for review",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "pending_review"


def test_invalid_status_transition(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "completed",
            "reason": "Try invalid transition",
        },
    )

    assert response.status_code == 400


def test_same_status_transition(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id)

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "open",
            "reason": "Status remains unchanged",
        },
    )

    assert response.status_code == 400


def test_complete_investigation_and_reopen_progress(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id, UserRole.SECURITY_MANAGER)

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "in_progress",
            "reason": "Start investigation",
        },
    )
    assert response.status_code == 200, response.text

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "completed",
            "reason": "Investigation completed",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["completed_at"] is not None

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "closed",
            "reason": "Close completed investigation",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "closed"


def test_manager_can_close_open_investigation(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)
    set_actor(user_id, UserRole.SECURITY_MANAGER)

    response = client.patch(
        f"/investigations/{investigation['id']}/status",
        json={
            "status": "closed",
            "reason": "Close investigation",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "closed"


def test_history_for_missing_investigation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/investigations/999999/history")

    assert response.status_code == 404


def test_investigation_history(client):
    user_id = register_user(client)
    investigation = create_investigation(client, user_id)

    response = client.get(
        f"/investigations/{investigation['id']}/history"
    )

    assert response.status_code == 200, response.text
    assert any(
        entry["action"] == "created"
        for entry in response.json()
    )
