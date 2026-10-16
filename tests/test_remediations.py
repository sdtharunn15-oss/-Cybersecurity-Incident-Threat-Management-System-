from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.organization import (
    Organization, Department, Asset, AssetType,
    AssetCriticality, AssetStatus,
)
from app.models.vulnerability import (
    Vulnerability, VulnerabilitySeverity, VulnerabilityStatus,
)
from app.models.remediation import (
    RemediationTask, RemediationHistory,
    RemediationStatus, RemediationPriority,
)


def register_user(client):
    email = f"rem-{uuid4().hex[:10]}@example.com"
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Remediation Test User",
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SECURITY_ANALYST, is_active=True):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id, role=role, is_active=is_active
    )


def get_test_db():
    return next(app.dependency_overrides[get_db]())


def create_vulnerability(user_id):
    db = get_test_db()
    suffix = uuid4().hex[:8]
    try:
        organization = Organization(
            name=f"Remediation Org {suffix}",
            description="Test organization",
        )
        db.add(organization)
        db.flush()

        department = Department(
            name=f"Remediation Dept {suffix}",
            organization_id=organization.id,
        )
        db.add(department)
        db.flush()

        asset = Asset(
            name=f"Remediation Server {suffix}",
            asset_tag=f"REM-{suffix}",
            asset_type=AssetType.SERVER,
            criticality=AssetCriticality.HIGH,
            status=AssetStatus.ACTIVE,
            organization_id=organization.id,
            department_id=department.id,
        )
        db.add(asset)
        db.flush()

        vulnerability = Vulnerability(
            title=f"Remediation vulnerability {suffix}",
            description="Test vulnerability description",
            severity=VulnerabilitySeverity.HIGH,
            cvss_score=7.5,
            affected_asset_id=asset.id,
            remediation_recommendation="Apply security patch",
            status=VulnerabilityStatus.OPEN,
            created_by_id=user_id,
        )
        db.add(vulnerability)
        db.commit()
        db.refresh(vulnerability)
        return vulnerability.id
    finally:
        db.close()


def create_task(client, vulnerability_id, assigned_to_id=None, due_date=None):
    payload = {
        "title": f"Patch task {uuid4().hex[:6]}",
        "description": "Apply and verify the security patch",
        "vulnerability_id": vulnerability_id,
        "priority": "high",
    }
    if assigned_to_id is not None:
        payload["assigned_to_id"] = assigned_to_id
    if due_date is not None:
        payload["due_date"] = due_date.isoformat()

    response = client.post("/remediations/", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_create_remediation_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    response = client.post(
        "/remediations/",
        json={
            "title": "Install security patch",
            "description": "Patch the affected server",
            "vulnerability_id": vulnerability_id,
            "priority": "critical",
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["status"] == "open"
    assert response.json()["priority"] == "critical"


def test_create_remediation_with_assignee(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    task = create_task(client, vulnerability_id, assigned_to_id=assignee_id)

    assert task["assigned_to_id"] == assignee_id
    assert task["status"] == "assigned"


def test_create_remediation_missing_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/remediations/",
        json={
            "title": "Patch missing vulnerability",
            "description": "Test missing vulnerability",
            "vulnerability_id": 999999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Vulnerability not found"


def test_create_remediation_missing_assignee(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    response = client.post(
        "/remediations/",
        json={
            "title": "Patch assignment test",
            "description": "Test invalid assignee",
            "vulnerability_id": vulnerability_id,
            "assigned_to_id": 999999,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Assignee not found"


def test_create_remediation_past_due_date(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    response = client.post(
        "/remediations/",
        json={
            "title": "Past due patch",
            "description": "Test past due date",
            "vulnerability_id": vulnerability_id,
            "due_date": (
                datetime.now(timezone.utc) - timedelta(days=1)
            ).isoformat(),
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Due date must be in the future"


def test_create_remediation_validation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/remediations/",
        json={
            "title": "x",
            "description": "ok",
            "vulnerability_id": 1,
        },
    )

    assert response.status_code == 422


def test_list_remediations_and_filters(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    create_task(client, vulnerability_id)
    create_task(
        client,
        vulnerability_id,
        due_date=datetime.now(timezone.utc) + timedelta(days=5),
    )

    response = client.get("/remediations/")
    assert response.status_code == 200, response.text
    assert len(response.json()) == 2

    response = client.get("/remediations/?priority=high")
    assert response.status_code == 200
    assert len(response.json()) == 2

    response = client.get(
        f"/remediations/?vulnerability_id={vulnerability_id}"
    )
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_list_remediations_invalid_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/remediations/?limit=0")
    assert response.status_code == 422

    response = client.get("/remediations/?skip=-1")
    assert response.status_code == 422


def test_assigned_to_me(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    create_task(client, vulnerability_id, assigned_to_id=assignee_id)

    set_actor(assignee_id)
    response = client.get("/remediations/assigned-to-me")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["assigned_to_id"] == assignee_id


def test_get_remediation_and_missing_task(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.get(f"/remediations/{task['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == task["id"]

    response = client.get("/remediations/999999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Remediation task not found"


def test_update_remediation(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.patch(
        f"/remediations/{task['id']}",
        json={"title": "Updated remediation title", "priority": "critical"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["title"] == "Updated remediation title"
    assert response.json()["priority"] == "critical"


def test_update_missing_remediation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/remediations/999999",
        json={"title": "Updated remediation title"},
    )
    assert response.status_code == 404


def test_closed_remediation_cannot_be_updated(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    db = get_test_db()
    try:
        item = db.query(RemediationTask).filter_by(id=task["id"]).first()
        item.status = RemediationStatus.COMPLETED
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/remediations/{task['id']}",
        json={"title": "Should not update"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Closed remediation tasks cannot be edited"


def test_assign_remediation(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.patch(
        f"/remediations/{task['id']}/assign",
        json={
            "assigned_to_id": assignee_id,
            "reason": "Assign to security engineer",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["assigned_to_id"] == assignee_id
    assert response.json()["status"] == "assigned"


def test_assign_missing_user(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.patch(
        f"/remediations/{task['id']}/assign",
        json={"assigned_to_id": 999999, "reason": "Invalid assignee"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Assignee not found"


def test_assign_closed_task_rejected(client):
    user_id = register_user(client)
    assignee_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    db = get_test_db()
    try:
        item = db.query(RemediationTask).filter_by(id=task["id"]).first()
        item.status = RemediationStatus.CANCELLED
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/remediations/{task['id']}/assign",
        json={"assigned_to_id": assignee_id, "reason": "Reassignment attempt"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Cannot assign a closed task"


def test_status_transition_to_in_progress(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.patch(
        f"/remediations/{task['id']}/status",
        json={"status": "in_progress", "reason": "Work started"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "in_progress"


def test_same_status_transition_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.patch(
        f"/remediations/{task['id']}/status",
        json={"status": "open", "reason": "No change"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Task already has this status"


def test_invalid_status_transition_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.patch(
        f"/remediations/{task['id']}/status",
        json={"status": "verified", "reason": "Invalid direct verification"},
    )

    assert response.status_code == 400
    assert "Cannot change status" in response.json()["detail"]


def test_analyst_cannot_verify_remediation(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    db = get_test_db()
    try:
        item = db.query(RemediationTask).filter_by(id=task["id"]).first()
        item.status = RemediationStatus.COMPLETED
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/remediations/{task['id']}/status",
        json={"status": "verified", "reason": "Attempt verification"},
    )

    assert response.status_code == 403
    assert "Only a Super Admin or Security Manager" in response.json()["detail"]


def test_manager_can_verify_remediation(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_MANAGER)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    db = get_test_db()
    try:
        item = db.query(RemediationTask).filter_by(id=task["id"]).first()
        item.status = RemediationStatus.COMPLETED
        db.commit()
    finally:
        db.close()

    response = client.patch(
        f"/remediations/{task['id']}/status",
        json={
            "status": "verified",
            "reason": "Patch verified",
            "completion_notes": "Validation passed",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "verified"


def test_complete_remediation_and_reopen(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    started = client.patch(
        f"/remediations/{task['id']}/status",
        json={"status": "in_progress", "reason": "Starting patch"},
    )
    assert started.status_code == 200, started.text

    completed = client.patch(
        f"/remediations/{task['id']}/status",
        json={
            "status": "completed",
            "reason": "Patch installed",
            "completion_notes": "Patch applied successfully",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["completed_at"] is not None

    reopened = client.patch(
        f"/remediations/{task['id']}/status",
        json={"status": "in_progress", "reason": "Additional validation needed"},
    )
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "in_progress"
    assert reopened.json()["completed_at"] is None


def test_remediation_history(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)
    task = create_task(client, vulnerability_id)

    response = client.get(f"/remediations/{task['id']}/history")
    assert response.status_code == 200, response.text
    assert len(response.json()) >= 1
    assert response.json()[0]["action"] == "created"


def test_history_missing_remediation(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/remediations/999999/history")
    assert response.status_code == 404
    assert response.json()["detail"] == "Remediation task not found"


def test_overdue_filter_excludes_closed_tasks(client):
    user_id = register_user(client)
    set_actor(user_id)
    vulnerability_id = create_vulnerability(user_id)

    overdue_task = create_task(
        client,
        vulnerability_id,
        due_date=datetime.now(timezone.utc) + timedelta(days=1),
    )

    db = get_test_db()
    try:
        item = db.query(RemediationTask).filter_by(id=overdue_task["id"]).first()
        item.due_date = datetime.now(timezone.utc) - timedelta(days=2)
        db.commit()
    finally:
        db.close()

    response = client.get("/remediations/?overdue_only=true")
    assert response.status_code == 200, response.text
    assert len(response.json()) == 1

    db = get_test_db()
    try:
        item = db.query(RemediationTask).filter_by(id=overdue_task["id"]).first()
        item.status = RemediationStatus.COMPLETED
        db.commit()
    finally:
        db.close()

    response = client.get("/remediations/?overdue_only=true")
    assert response.status_code == 200, response.text
    assert response.json() == []
