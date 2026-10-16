
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.organization import (
    Organization,
    Department,
    Asset,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityHistory,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)


def register_user(client, email=None):
    email = email or f"vuln-{uuid4().hex[:8]}@example.com"
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Vulnerability Test User",
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SECURITY_ANALYST, is_active=True):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
        is_active=is_active,
    )


def get_test_db():
    return next(app.dependency_overrides[get_db]())


def create_asset():
    db = get_test_db()
    suffix = uuid4().hex[:8]
    try:
        organization = Organization(
            name=f"Vulnerability Organization {suffix}",
            description="Organization for vulnerability tests",
        )
        db.add(organization)
        db.flush()

        department = Department(
            name=f"Vulnerability Department {suffix}",
            organization_id=organization.id,
        )
        db.add(department)
        db.flush()

        asset = Asset(
            name=f"Vulnerability Server {suffix}",
            asset_tag=f"VULN-{suffix}",
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


def create_vulnerability(
    user_id,
    asset_id,
    title=None,
    severity=VulnerabilitySeverity.HIGH,
    status=VulnerabilityStatus.OPEN,
    cve_id=None,
    deadline=None,
):
    db = get_test_db()
    try:
        item = Vulnerability(
            title=title or f"Test vulnerability {uuid4().hex[:6]}",
            description="A test vulnerability description",
            cve_id=cve_id,
            severity=severity,
            cvss_score=7.5,
            affected_asset_id=asset_id,
            remediation_recommendation="Apply the recommended security patch",
            status=status,
            remediation_deadline=deadline,
            created_by_id=user_id,
        )
        db.add(item)
        db.commit()
        db.refresh(item)
        return item.id
    finally:
        db.close()


def test_create_vulnerability_success(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    response = client.post(
        "/vulnerabilities",
        json={
            "title": "Remote code execution",
            "description": "Remote execution vulnerability in a service",
            "cve_id": " cve-2025-12345 ",
            "severity": "critical",
            "cvss_score": 9.5,
            "affected_asset_id": asset_id,
            "remediation_recommendation": "Install the security patch",
        },
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data["cve_id"] == "CVE-2025-12345"
    assert data["severity"] == "critical"
    assert data["status"] == "open"


def test_create_vulnerability_missing_asset(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/vulnerabilities",
        json={
            "title": "Missing asset vulnerability",
            "description": "This references a missing asset",
            "severity": "high",
            "affected_asset_id": 999999,
            "remediation_recommendation": "Install the security patch",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Affected asset not found."


def test_create_vulnerability_duplicate_cve(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    payload = {
        "title": "Duplicate CVE vulnerability",
        "description": "A vulnerability with a unique CVE identifier",
        "cve_id": "CVE-2025-12345",
        "severity": "high",
        "affected_asset_id": asset_id,
        "remediation_recommendation": "Install the security patch",
    }

    first = client.post("/vulnerabilities", json=payload)
    assert first.status_code == 201, first.text

    payload["title"] = "Second vulnerability with same CVE"
    second = client.post("/vulnerabilities", json=payload)

    assert second.status_code == 409
    assert second.json()["detail"] == "This CVE identifier is already registered."


def test_create_vulnerability_past_deadline(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    response = client.post(
        "/vulnerabilities",
        json={
            "title": "Past deadline vulnerability",
            "description": "This vulnerability has a past deadline",
            "severity": "high",
            "affected_asset_id": asset_id,
            "remediation_recommendation": "Install the security patch",
            "remediation_deadline": (
                datetime.now(timezone.utc) - timedelta(days=1)
            ).isoformat(),
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Remediation deadline must be in the future."


def test_create_vulnerability_invalid_cve(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    response = client.post(
        "/vulnerabilities",
        json={
            "title": "Invalid CVE vulnerability",
            "description": "An invalid CVE identifier is supplied",
            "cve_id": "INVALID-123",
            "severity": "high",
            "affected_asset_id": asset_id,
            "remediation_recommendation": "Install the security patch",
        },
    )

    assert response.status_code == 422


def test_list_vulnerabilities(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    create_vulnerability(user_id, asset_id)

    response = client.get("/vulnerabilities")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1


def test_list_vulnerabilities_search(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    create_vulnerability(
        user_id,
        asset_id,
        title="Unique SQL injection issue",
    )

    response = client.get("/vulnerabilities?q=SQL injection")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert "SQL injection" in response.json()[0]["title"]


def test_list_vulnerabilities_filter_severity(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    create_vulnerability(
        user_id, asset_id, severity=VulnerabilitySeverity.CRITICAL
    )
    create_vulnerability(
        user_id, asset_id, severity=VulnerabilitySeverity.LOW
    )

    response = client.get("/vulnerabilities?severity=critical")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["severity"] == "critical"


def test_list_vulnerabilities_filter_status(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    create_vulnerability(
        user_id, asset_id, status=VulnerabilityStatus.UNDER_REVIEW
    )
    create_vulnerability(
        user_id, asset_id, status=VulnerabilityStatus.OPEN
    )

    response = client.get("/vulnerabilities?status=under_review")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["status"] == "under_review"


def test_list_vulnerabilities_filter_asset_and_cve(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    other_asset_id = create_asset()

    create_vulnerability(
        user_id, asset_id, cve_id="CVE-2025-54321"
    )
    create_vulnerability(
        user_id, other_asset_id, cve_id="CVE-2025-67890"
    )

    response = client.get(
        f"/vulnerabilities?asset_id={asset_id}&cve_id=cve-2025-54321"
    )

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["cve_id"] == "CVE-2025-54321"


def test_list_vulnerabilities_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    for index in range(3):
        create_vulnerability(user_id, asset_id, title=f"Pagination issue {index}")

    response = client.get("/vulnerabilities?page=1&page_size=2")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 2


def test_list_vulnerabilities_invalid_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/vulnerabilities?page=0")

    assert response.status_code == 422


def test_list_vulnerabilities_overdue_only(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    create_vulnerability(
        user_id,
        asset_id,
        title="Overdue issue",
        deadline=datetime.now(timezone.utc) - timedelta(days=2),
    )
    create_vulnerability(
        user_id,
        asset_id,
        title="Future deadline issue",
        deadline=datetime.now(timezone.utc) + timedelta(days=5),
    )

    response = client.get("/vulnerabilities?overdue_only=true")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["title"] == "Overdue issue"


def test_get_vulnerability_by_id(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.get(f"/vulnerabilities/{vulnerability_id}")

    assert response.status_code == 200, response.text
    assert response.json()["id"] == vulnerability_id


def test_get_missing_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/vulnerabilities/999999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Vulnerability not found."


def test_update_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}",
        json={
            "title": "Updated vulnerability title",
            "severity": "critical",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["title"] == "Updated vulnerability title"
    assert response.json()["severity"] == "critical"


def test_update_missing_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/vulnerabilities/999999",
        json={"title": "Updated vulnerability title"},
    )

    assert response.status_code == 404


def test_closed_vulnerability_cannot_be_updated(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(
        user_id, asset_id, status=VulnerabilityStatus.CLOSED
    )

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}",
        json={"title": "Attempt to edit closed vulnerability"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Closed vulnerabilities cannot be edited."


def test_update_vulnerability_validation(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}",
        json={"title": "x"},
    )

    assert response.status_code == 422


def test_valid_status_transition(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}/status",
        json={"status": "under_review", "reason": "Initial review"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "under_review"


def test_same_status_transition_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}/status",
        json={"status": "open"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Vulnerability already has this status."


def test_invalid_status_transition_rejected(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}/status",
        json={"status": "mitigated"},
    )

    assert response.status_code == 400
    assert "Invalid status transition" in response.json()["detail"]


def test_analyst_cannot_accept_risk(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_ANALYST)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}/status",
        json={"status": "accepted_risk", "reason": "Business decision"},
    )

    assert response.status_code == 403
    assert "Only a Super Admin or Security Manager" in response.json()["detail"]


def test_manager_can_accept_risk(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_MANAGER)
    asset_id = create_asset()
    vulnerability_id = create_vulnerability(user_id, asset_id)

    response = client.patch(
        f"/vulnerabilities/{vulnerability_id}/status",
        json={"status": "accepted_risk", "reason": "Approved by manager"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "accepted_risk"



def test_vulnerability_history(client):
    user_id = register_user(client)
    asset_id = create_asset()
    set_actor(user_id)

    response = client.post(
        "/vulnerabilities",
        json={
            "title": "History Test Vulnerability",
            "description": "Testing vulnerability history records.",
            "severity": "high",
            "affected_asset_id": asset_id,
            "remediation_recommendation": "Apply the latest security patch.",
        },
    )

    assert response.status_code == 201, response.text
    vulnerability_id = response.json()["id"]

    history_response = client.get(
        f"/vulnerabilities/{vulnerability_id}/history"
    )

    assert history_response.status_code == 200, history_response.text
    history = history_response.json()

    assert len(history) >= 1
    assert history[0]["field_name"] == "created"

def test_history_missing_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/vulnerabilities/999999/history")

    assert response.status_code == 404


def test_auditor_cannot_create_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.AUDITOR)
    asset_id = create_asset()

    response = client.post(
        "/vulnerabilities",
        json={
            "title": "Auditor create attempt",
            "description": "Attempt to create a vulnerability",
            "severity": "high",
            "affected_asset_id": asset_id,
            "remediation_recommendation": "Install the security patch",
        },
    )

    assert response.status_code == 403


def test_inactive_user_cannot_list_vulnerabilities(client):
    user_id = register_user(client)
    set_actor(user_id, is_active=False)

    response = client.get("/vulnerabilities")

    assert response.status_code == 403
    assert response.json()["detail"] == "Account is inactive."
