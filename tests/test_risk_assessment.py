
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.organization import (
    Organization,
    Department,
    Asset,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
from app.models.risk_assessment import (
    RiskAssessment,
    RiskAssessmentHistory,
    RiskLevel,
    RiskStatus,
)


def register_user(client, email="risk-user@example.com"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Risk Test User",
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=None):
    if role is None:
        from app.models.user import UserRole
        role = UserRole.SECURITY_ANALYST

    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
    )


def get_test_db():
    db_dependency = app.dependency_overrides[get_db]
    return next(db_dependency())


def create_asset(criticality=AssetCriticality.HIGH):
    db = get_test_db()
    suffix = uuid4().hex[:8]

    try:
        organization = Organization(
            name=f"Risk Test Organization {suffix}",
            description="Organization for risk tests",
        )
        db.add(organization)
        db.flush()

        department = Department(
            name=f"Risk Test Department {suffix}",
            organization_id=organization.id,
        )
        db.add(department)
        db.flush()

        asset = Asset(
            name=f"Risk Test Server {suffix}",
            asset_tag=f"RISK-{suffix}",
            asset_type=AssetType.SERVER,
            criticality=criticality,
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


def create_assessment(
    asset_id,
    user_id,
    score=80.0,
    level=RiskLevel.critical,
    assessment_status=RiskStatus.open,
):
    db = get_test_db()
    try:
        assessment = RiskAssessment(
            asset_id=asset_id,
            risk_score=score,
            risk_level=level,
            status=assessment_status,
            findings_summary="Test risk assessment findings",
            assessed_by_id=user_id,
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        return assessment.id
    finally:
        db.close()


def test_calculate_risk_creates_assessment(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset(AssetCriticality.CRITICAL)

    response = client.post(
        f"/risk-assessments/assets/{asset_id}/calculate"
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["asset_id"] == asset_id
    assert data["risk_score"] == 40.0
    assert data["risk_level"] == "medium"
    assert data["status"] == "open"
    assert "Active vulnerabilities: 0." in data["findings_summary"]


def test_calculate_risk_missing_asset(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post("/risk-assessments/assets/99999/calculate")

    assert response.status_code == 404
    assert response.json()["detail"] == "Asset not found"


def test_calculate_risk_recalculates_existing_assessment(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset(AssetCriticality.CRITICAL)

    assessment_id = create_assessment(
        asset_id,
        user_id,
        score=95.0,
        level=RiskLevel.critical,
    )

    response = client.post(
        f"/risk-assessments/assets/{asset_id}/calculate"
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["id"] == assessment_id
    assert data["risk_score"] == 40.0
    assert data["risk_level"] == "medium"

    db = get_test_db()
    try:
        history = (
            db.query(RiskAssessmentHistory)
            .filter(RiskAssessmentHistory.assessment_id == assessment_id)
            .all()
        )
        assert any(item.action == "recalculated" for item in history)
    finally:
        db.close()


def test_list_risk_assessments(client):
    user_id = register_user(client)
    set_actor(user_id)

    asset_id = create_asset()
    create_assessment(asset_id, user_id)

    response = client.get("/risk-assessments/")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["asset_id"] == asset_id


def test_list_risk_assessments_filter_by_level(client):
    user_id = register_user(client)
    set_actor(user_id)

    critical_asset_id = create_asset()
    low_asset_id = create_asset(AssetCriticality.LOW)

    create_assessment(
        critical_asset_id,
        user_id,
        score=90,
        level=RiskLevel.critical,
    )
    create_assessment(
        low_asset_id,
        user_id,
        score=10,
        level=RiskLevel.low,
    )

    response = client.get("/risk-assessments/?level=critical")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["risk_level"] == "critical"

from app.models.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.models.user import UserRole


def create_vulnerability(
    asset_id,
    user_id,
    severity=VulnerabilitySeverity.HIGH,
    cvss_score=8.0,
    status=VulnerabilityStatus.OPEN,
):
    db = get_test_db()
    try:
        vulnerability = Vulnerability(
            title=f"Test vulnerability {uuid4().hex[:8]}",
            description="Created for risk assessment coverage testing",
            severity=severity,
            cvss_score=cvss_score,
            affected_asset_id=asset_id,
            remediation_recommendation="Apply the recommended security patch",
            status=status,
            created_by_id=user_id,
        )
        db.add(vulnerability)
        db.commit()
        db.refresh(vulnerability)
        return vulnerability.id
    finally:
        db.close()


def test_calculate_risk_with_active_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset(AssetCriticality.CRITICAL)

    create_vulnerability(
        asset_id,
        user_id,
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=10.0,
    )

    response = client.post(
        f"/risk-assessments/assets/{asset_id}/calculate"
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["risk_score"] == 100.0
    assert data["risk_level"] == "critical"
    assert "Active vulnerabilities: 1." in data["findings_summary"]


def test_calculate_risk_ignores_mitigated_and_closed_vulnerabilities(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset(AssetCriticality.CRITICAL)

    create_vulnerability(
        asset_id, user_id,
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=10.0,
        status=VulnerabilityStatus.MITIGATED,
    )
    create_vulnerability(
        asset_id, user_id,
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=10.0,
        status=VulnerabilityStatus.CLOSED,
    )

    response = client.post(
        f"/risk-assessments/assets/{asset_id}/calculate"
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["risk_score"] == 40.0
    assert "Active vulnerabilities: 0." in data["findings_summary"]


def test_list_risk_assessments_with_multiple_filters(client):
    user_id = register_user(client)
    set_actor(user_id)

    critical_asset = create_asset()
    low_asset = create_asset(AssetCriticality.LOW)

    critical_id = create_assessment(
        critical_asset, user_id,
        score=90,
        level=RiskLevel.critical,
        assessment_status=RiskStatus.open,
    )
    create_assessment(
        low_asset, user_id,
        score=10,
        level=RiskLevel.low,
        assessment_status=RiskStatus.remediated,
    )

    response = client.get(
        f"/risk-assessments/?status=open&asset_id={critical_asset}"
    )

    assert response.status_code == 200, response.text
    assert [item["id"] for item in response.json()] == [critical_id]


def test_list_risk_assessments_high_risk_only(client):
    user_id = register_user(client)
    set_actor(user_id)

    high_asset = create_asset()
    low_asset = create_asset(AssetCriticality.LOW)

    create_assessment(
        high_asset, user_id, score=80, level=RiskLevel.high
    )
    create_assessment(
        low_asset, user_id, score=10, level=RiskLevel.low
    )

    response = client.get("/risk-assessments/?high_risk_only=true")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["risk_level"] == "high"


def test_list_risk_assessments_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    asset_ids = [create_asset() for _ in range(3)]
    for index, asset_id in enumerate(asset_ids):
        create_assessment(
            asset_id, user_id,
            score=20 + index * 10,
            level=RiskLevel.low,
        )

    response = client.get("/risk-assessments/?skip=1&limit=1")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["risk_score"] == 30.0


def test_high_risk_assets_excludes_remediated(client):
    user_id = register_user(client)
    set_actor(user_id)

    active_asset = create_asset()
    remediated_asset = create_asset()

    create_assessment(
        active_asset, user_id,
        score=90, level=RiskLevel.critical,
        assessment_status=RiskStatus.open,
    )
    create_assessment(
        remediated_asset, user_id,
        score=85, level=RiskLevel.high,
        assessment_status=RiskStatus.remediated,
    )

    response = client.get("/risk-assessments/high-risk-assets")

    assert response.status_code == 200, response.text
    assert len(response.json()) == 1
    assert response.json()[0]["asset_id"] == active_asset


def test_update_risk_status_missing_assessment(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.patch(
        "/risk-assessments/99999/status",
        json={"status": "remediated", "reason": "Patch completed"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Risk assessment not found"


def test_analyst_cannot_accept_risk(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_ANALYST)
    asset_id = create_asset()
    assessment_id = create_assessment(asset_id, user_id)

    response = client.patch(
        f"/risk-assessments/{assessment_id}/status",
        json={"status": "accepted_risk", "reason": "Business exception"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Only a Super Admin or Security Manager can accept risk"
    )


def test_manager_can_accept_risk_and_history_is_written(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_MANAGER)
    asset_id = create_asset()
    assessment_id = create_assessment(asset_id, user_id)

    response = client.patch(
        f"/risk-assessments/{assessment_id}/status",
        json={
            "status": "accepted_risk",
            "reason": "Temporary exception approved",
        },
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "accepted_risk"
    assert data["accepted_by_id"] == user_id
    assert data["accepted_reason"] == "Temporary exception approved"

    history_response = client.get(
        f"/risk-assessments/{assessment_id}/history"
    )
    assert history_response.status_code == 200
    assert any(
        item["action"] == "status_changed"
        and item["new_value"] == "accepted_risk"
        for item in history_response.json()
    )


def test_changing_accepted_risk_clears_acceptance_fields(client):
    user_id = register_user(client)
    set_actor(user_id, UserRole.SECURITY_MANAGER)
    asset_id = create_asset()
    assessment_id = create_assessment(asset_id, user_id)

    accepted = client.patch(
        f"/risk-assessments/{assessment_id}/status",
        json={"status": "accepted_risk", "reason": "Approved exception"},
    )
    assert accepted.status_code == 200, accepted.text

    set_actor(user_id, UserRole.SECURITY_ANALYST)
    response = client.patch(
        f"/risk-assessments/{assessment_id}/status",
        json={"status": "remediated", "reason": "Risk has been fixed"},
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "remediated"
    assert data["accepted_by_id"] is None
    assert data["accepted_reason"] is None


def test_update_risk_status_rejects_short_reason(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    assessment_id = create_assessment(asset_id, user_id)

    response = client.patch(
        f"/risk-assessments/{assessment_id}/status",
        json={"status": "remediated", "reason": "ok"},
    )

    assert response.status_code == 422


def test_risk_history_missing_assessment(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/risk-assessments/99999/history")

    assert response.status_code == 404
    assert response.json()["detail"] == "Risk assessment not found"


def test_risk_history_includes_creation_entry(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    assessment_id = create_assessment(asset_id, user_id)

    db = get_test_db()
    try:
        assessment = db.query(RiskAssessment).filter(
            RiskAssessment.id == assessment_id
        ).first()
        from app.api.risk_assessment.routes import write_history

        write_history(
            db,
            assessment,
            user_id,
            "test_action",
            old_value=None,
            new_value="created",
            reason="History coverage test",
        )
        db.commit()
    finally:
        db.close()

    response = client.get(
        f"/risk-assessments/{assessment_id}/history"
    )

    assert response.status_code == 200, response.text
    assert any(
        item["action"] == "test_action"
        and item["old_value"] is None
        and item["new_value"] == "created"
        for item in response.json()
    )
