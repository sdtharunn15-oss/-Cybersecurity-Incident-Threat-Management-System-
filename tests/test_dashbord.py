
from types import SimpleNamespace
from uuid import uuid4

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.incident import SecurityIncident, IncidentStatus
from app.models.alert import SecurityAlert
from app.models.vulnerability import Vulnerability


def register_user(client):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Dashboard Tester",
            "email": f"dashboard_{uuid4().hex[:10]}@example.com",
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
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)
    return db, db_generator


def test_dashboard_summary_empty_database(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text
    data = response.json()

    assert data["total_incidents"] == 0
    assert data["open_incidents"] == 0
    assert data["resolved_incidents"] == 0
    assert data["incidents_by_status"] == {}
    assert data["critical_alerts"] == 0
    assert data["vulnerabilities_by_severity"] == {}
    assert data["high_risk_assets"] == 0
    assert data["sla_compliance_percent"] is None
    assert data["overdue_remediation_tasks"] == 0
    assert data["analyst_workload"] == []
    assert data["incident_trends_last_30_days"] == []


def test_dashboard_summary_returns_expected_keys(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text

    expected_keys = {
        "total_incidents",
        "open_incidents",
        "resolved_incidents",
        "incidents_by_status",
        "critical_alerts",
        "vulnerabilities_by_severity",
        "high_risk_assets",
        "average_response_time",
        "sla_compliance_percent",
        "overdue_remediation_tasks",
        "analyst_workload",
        "incident_trends_last_30_days",
    }
    assert expected_keys.issubset(response.json().keys())


def test_normalize_handles_none_and_strings():
    from app.api.dashboard.routes import normalize

    assert normalize(None) == ""
    assert normalize("CRITICAL") == "critical"
    assert normalize(SimpleNamespace(value="HIGH")) == "high"


def test_grouped_counts_missing_field(client):
    from app.api.dashboard.routes import grouped_counts

    user_id = register_user(client)
    set_actor(user_id)
    db, db_generator = get_test_db()

    try:
        assert grouped_counts(db, SecurityIncident, "missing_field") == {}
    finally:
        db.close()
        db_generator.close()


def test_dashboard_summary_with_incident(client):
    user_id = register_user(client)
    set_actor(user_id)

    db, db_generator = get_test_db()
    try:
        incident = SecurityIncident(
            incident_number=f"INC-{uuid4().hex[:10]}",
            title="Dashboard test incident",
            description="Incident created for dashboard testing",
            status=IncidentStatus.NEW,
            created_by_id=user_id,
            assigned_to_id=user_id,
        )
        db.add(incident)
        db.commit()
    finally:
        db.close()
        db_generator.close()

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text
    data = response.json()

    assert data["total_incidents"] == 1
    assert data["open_incidents"] == 1
    assert data["incidents_by_status"].get("new") == 1


def test_dashboard_summary_resolved_incident(client):
    user_id = register_user(client)
    set_actor(user_id)

    db, db_generator = get_test_db()
    try:
        incident = SecurityIncident(
            incident_number=f"INC-{uuid4().hex[:10]}",
            title="Resolved dashboard incident",
            description="Resolved incident for dashboard testing",
            status=IncidentStatus.RESOLVED,
            created_by_id=user_id,
            assigned_to_id=user_id,
        )
        db.add(incident)
        db.commit()
    finally:
        db.close()
        db_generator.close()

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text
    data = response.json()

    assert data["total_incidents"] == 1
    assert data["resolved_incidents"] == 1
    assert data["open_incidents"] == 0
    assert data["incidents_by_status"].get("resolved") == 1


def test_dashboard_summary_with_critical_alert(client):
    user_id = register_user(client)
    set_actor(user_id)

    # Create a valid asset using the existing project test helper.
    from tests.test_vulnerabilities import create_asset

    asset_id = create_asset()

    db, db_generator = get_test_db()
    try:
        alert = SecurityAlert(
            title="Critical dashboard alert",
            description="Critical alert for dashboard testing",
            source="dashboard_test",
            category="security",
            severity="critical",
            asset_id=asset_id,
            created_by_id=user_id,
        )
        db.add(alert)
        db.commit()
    finally:
        db.close()
        db_generator.close()

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text
    assert response.json()["critical_alerts"] == 1


def test_dashboard_summary_with_vulnerability(client):
    user_id = register_user(client)
    set_actor(user_id)

    from tests.test_vulnerabilities import create_asset

    asset_id = create_asset()

    db, db_generator = get_test_db()
    try:
        vulnerability = Vulnerability(
            title="Dashboard vulnerability",
            description="Vulnerability for dashboard testing",
            severity="high",
            affected_asset_id=asset_id,
            remediation_recommendation="Apply the security patch",
            created_by_id=user_id,
        )
        db.add(vulnerability)
        db.commit()
    finally:
        db.close()
        db_generator.close()

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text
    assert response.json()["vulnerabilities_by_severity"].get("high") == 1


def test_dashboard_summary_without_sla_records(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/dashboard/summary")

    assert response.status_code == 200, response.text
    assert response.json()["sla_compliance_percent"] is None
    assert response.json()["average_response_time"] is None
