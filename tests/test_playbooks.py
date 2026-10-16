
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.playbook import (
    ResponsePlaybook,
    ResponsePlaybookStep,
    PlaybookExecution,
    PlaybookExecutionStep,
    PlaybookStatus,
    PlaybookExecutionStatus,
    PlaybookStepStatus,
)


def register_user(client):
    email = f"playbook-{uuid4().hex[:10]}@example.com"
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Playbook Test User",
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(
    user_id,
    role=UserRole.SECURITY_MANAGER,
    is_active=True,
):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
        is_active=is_active,
    )


def get_test_db():
    return next(app.dependency_overrides[get_db]())


def create_playbook(client, name=None, steps=None):
    payload = {
        "name": name or f"Test Playbook {uuid4().hex[:6]}",
        "description": "Test incident response playbook",
        "category": "incident_response",
        "steps": steps or [
            {
                "step_number": 1,
                "title": "Investigate alert",
                "instructions": "Review the alert and collect evidence",
                "is_required": True,
            },
            {
                "step_number": 2,
                "title": "Document findings",
                "instructions": "Record findings and recommended actions",
                "is_required": False,
            },
        ],
    }
    response = client.post("/playbooks/", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def create_incident(user_id):
    db = get_test_db()
    try:
        from app.models.incident import SecurityIncident, IncidentStatus
        from app.models.alert import AlertSeverity

        incident = SecurityIncident(
            incident_number=f"PB-{uuid4().hex[:10]}",
            title="Playbook test incident",
            description="Incident created for playbook execution tests",
            severity=AlertSeverity.HIGH,
            status=IncidentStatus.NEW,
            created_by_id=user_id,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.id
    finally:
        db.close()


def activate_playbook(playbook_id):
    db = get_test_db()
    try:
        playbook = db.query(ResponsePlaybook).filter(
            ResponsePlaybook.id == playbook_id
        ).first()
        playbook.status = PlaybookStatus.ACTIVE
        db.commit()
    finally:
        db.close()


def make_inactive(playbook_id):
    db = get_test_db()
    try:
        playbook = db.query(ResponsePlaybook).filter(
            ResponsePlaybook.id == playbook_id
        ).first()
        playbook.status = PlaybookStatus.INACTIVE
        db.commit()
    finally:
        db.close()


def test_create_playbook_success(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/playbooks/",
        json={
            "name": "Malware Response",
            "description": "Respond to malware alerts",
            "category": "malware",
            "steps": [
                {
                    "step_number": 1,
                    "title": "Isolate host",
                    "instructions": "Disconnect the affected host",
                    "is_required": True,
                }
            ],
        },
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["name"] == "Malware Response"
    assert data["category"] == "malware"
    assert len(data["steps"]) == 1
    assert data["steps"][0]["step_number"] == 1
    assert data["created_by_id"] == user_id


def test_create_playbook_rejects_analyst(client):
    user_id = register_user(client)
    set_actor(user_id, role=UserRole.SECURITY_ANALYST)

    response = client.post(
        "/playbooks/",
        json={
            "name": "Unauthorized Playbook",
            "steps": [
                {
                    "step_number": 1,
                    "title": "Review",
                    "instructions": "Review the incident",
                }
            ],
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


def test_create_playbook_rejects_duplicate_step_numbers(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/playbooks/",
        json={
            "name": "Duplicate Steps",
            "steps": [
                {
                    "step_number": 1,
                    "title": "First",
                    "instructions": "First step",
                },
                {
                    "step_number": 1,
                    "title": "Second",
                    "instructions": "Second step",
                },
            ],
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Step numbers must be unique"


def test_create_playbook_rejects_invalid_payload(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/playbooks/",
        json={
            "name": "",
            "steps": [],
        },
    )

    assert response.status_code == 422


def test_list_playbooks(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_playbook(client, name="Playbook One")
    create_playbook(client, name="Playbook Two")

    response = client.get("/playbooks/")

    assert response.status_code == 200
    names = [item["name"] for item in response.json()]
    assert "Playbook One" in names
    assert "Playbook Two" in names


def test_get_playbook_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    created = create_playbook(client)

    response = client.get(f"/playbooks/{created['id']}")

    assert response.status_code == 200
    assert response.json()["id"] == created["id"]
    assert len(response.json()["steps"]) == 2


def test_get_missing_playbook(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/playbooks/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Playbook not found"


def test_update_playbook_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    created = create_playbook(client)

    response = client.patch(
        f"/playbooks/{created['id']}",
        json={
            "name": "Updated Playbook",
            "description": "Updated description",
            "category": "containment",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Updated Playbook"
    assert response.json()["description"] == "Updated description"
    assert response.json()["category"] == "containment"


def test_update_playbook_status(client):
    user_id = register_user(client)
    set_actor(user_id)
    created = create_playbook(client)

    response = client.patch(
        f"/playbooks/{created['id']}",
        json={"status": "inactive"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "inactive"


def test_update_playbook_rejects_analyst(client):
    user_id = register_user(client)
    set_actor(user_id, role=UserRole.SECURITY_MANAGER)
    created = create_playbook(client)

    set_actor(user_id, role=UserRole.SECURITY_ANALYST)
    response = client.patch(
        f"/playbooks/{created['id']}",
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


def test_update_missing_playbook(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/playbooks/999999",
        json={"name": "Missing"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Playbook not found"


def test_start_execution_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)

    response = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["playbook_id"] == playbook["id"]
    assert data["incident_id"] == incident_id
    assert data["status"] == "in_progress"
    assert len(data["steps"]) == 2


def test_start_execution_rejects_inactive_playbook(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    make_inactive(playbook["id"])
    incident_id = create_incident(user_id)

    response = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Active playbook not found"


def test_start_execution_rejects_missing_playbook(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/playbooks/999999/executions",
        json={"incident_id": 1},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Active playbook not found"


def test_start_execution_rejects_missing_incident(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)

    response = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": 999999},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"


def test_get_execution_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)

    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    )
    assert started.status_code == 201, started.text

    response = client.get(
        f"/playbooks/executions/{started.json()['id']}"
    )

    assert response.status_code == 200
    assert response.json()["id"] == started.json()["id"]


def test_get_execution_not_found(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/playbooks/executions/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Execution not found"


def test_update_execution_step_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)

    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    )
    assert started.status_code == 201, started.text
    execution = started.json()
    step_id = execution["steps"][0]["id"]

    response = client.patch(
        f"/playbooks/executions/{execution['id']}/steps/{step_id}",
        json={"status": "completed", "notes": "Investigation complete"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["message"] == "Execution step updated"

    db = get_test_db()
    try:
        step = db.query(PlaybookExecutionStep).filter(
            PlaybookExecutionStep.id == step_id
        ).first()
        assert step.status == PlaybookStepStatus.COMPLETED
        assert step.completed_by_id == user_id
        assert step.completed_at is not None
        assert step.notes == "Investigation complete"
    finally:
        db.close()


def test_update_execution_step_non_completed_status(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)
    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    )
    execution = started.json()
    step_id = execution["steps"][0]["id"]

    response = client.patch(
        f"/playbooks/executions/{execution['id']}/steps/{step_id}",
        json={"status": "in_progress", "notes": "Working on it"},
    )

    assert response.status_code == 200, response.text
    db = get_test_db()
    try:
        step = db.query(PlaybookExecutionStep).filter(
            PlaybookExecutionStep.id == step_id
        ).first()
        assert step.status == PlaybookStepStatus.IN_PROGRESS
        assert step.completed_at is None
    finally:
        db.close()


def test_update_execution_step_missing_execution(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/playbooks/executions/999999/steps/1",
        json={"status": "completed"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Execution not found"


def test_update_execution_step_missing_step(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)
    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    )
    execution_id = started.json()["id"]

    response = client.patch(
        f"/playbooks/executions/{execution_id}/steps/999999",
        json={"status": "completed"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Execution step not found"


def test_update_execution_step_rejects_step_from_other_execution(client):
    user_id = register_user(client)
    set_actor(user_id)

    playbook = create_playbook(client)
    incident_one = create_incident(user_id)
    incident_two = create_incident(user_id)

    first = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_one},
    ).json()
    second = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_two},
    ).json()

    response = client.patch(
        f"/playbooks/executions/{first['id']}/steps/{second['steps'][0]['id']}",
        json={"status": "completed"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Execution step not found"


def test_update_step_rejects_finished_execution(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)
    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    ).json()
    execution_id = started["id"]
    step_id = started["steps"][0]["id"]

    status_response = client.patch(
        f"/playbooks/executions/{execution_id}/status",
        json={"status": "cancelled", "summary": "Stopped"},
    )
    assert status_response.status_code == 200, status_response.text

    response = client.patch(
        f"/playbooks/executions/{execution_id}/steps/{step_id}",
        json={"status": "completed"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Execution is not in progress"


def test_update_execution_status_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)
    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    ).json()

    response = client.patch(
        f"/playbooks/executions/{started['id']}/status",
        json={"status": "failed", "summary": "Response unsuccessful"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "failed"
    assert response.json()["summary"] == "Response unsuccessful"


def test_complete_execution_rejects_required_pending_steps(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)
    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    ).json()

    response = client.patch(
        f"/playbooks/executions/{started['id']}/status",
        json={"status": "completed", "summary": "Done"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Complete all required steps before completing execution"
    )


def test_complete_execution_after_required_steps_completed(client):
    user_id = register_user(client)
    set_actor(user_id)
    playbook = create_playbook(client)
    incident_id = create_incident(user_id)
    started = client.post(
        f"/playbooks/{playbook['id']}/executions",
        json={"incident_id": incident_id},
    ).json()

    required_steps = [
        step for step in started["steps"]
        if step["step_number"] == 1
    ]
    assert required_steps

    for step in required_steps:
        response = client.patch(
            f"/playbooks/executions/{started['id']}/steps/{step['id']}",
            json={"status": "completed", "notes": "Completed"},
        )
        assert response.status_code == 200, response.text

    response = client.patch(
        f"/playbooks/executions/{started['id']}/status",
        json={"status": "completed", "summary": "All required steps done"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "completed"
    assert response.json()["completed_at"] is not None


def test_update_missing_execution_status(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/playbooks/executions/999999/status",
        json={"status": "failed", "summary": "Not found"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Execution not found"
