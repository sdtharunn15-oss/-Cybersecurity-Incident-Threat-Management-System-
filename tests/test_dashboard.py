
from datetime import datetime, timedelta
from uuid import uuid4

from app.api.dashboard.routes import normalize, grouped_counts
from app.models.incident import SecurityIncident, IncidentStatus


def register_user(client):
    email = f"dashboard_{uuid4().hex[:10]}@example.com"
    password = "StrongPassword123!"

    response = client.post(
        "/auth/register",
        json={
            "full_name": "Dashboard Tester",
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 201, response.text
    return {
        "id": response.json()["id"],
        "email": email,
        "password": password,
    }


def get_auth_headers(client, email=None, password=None):
    if email is None or password is None:
        user = register_user(client)
        email = user["email"]
        password = user["password"]

    response = client.post(
        "/auth/login",
        data={
            "username": email,
            "password": password,
        },
    )

    assert response.status_code == 200, response.text

    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_normalize_values():
    assert normalize(None) == ""
    assert normalize("CRITICAL") == "critical"
    assert normalize(10) == "10"


def test_grouped_counts_missing_field(client):
    from app import main
    from app.db.database import get_db

    override_db = main.app.dependency_overrides[get_db]
    db_generator = override_db()
    db = next(db_generator)

    try:
        assert grouped_counts(
            db, SecurityIncident, "missing_field"
        ) == {}
    finally:
        db.close()
        db_generator.close()


def test_dashboard_summary_empty_database(client):
    headers = get_auth_headers(client)

    response = client.get(
        "/dashboard/summary",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total_incidents"] == 0
    assert data["open_incidents"] == 0
    assert data["resolved_incidents"] == 0
    assert data["incidents_by_status"] == {}
    assert data["critical_alerts"] == 0
    assert data["vulnerabilities_by_severity"] == {}
    assert data["high_risk_assets"] == 0
    assert data["average_response_time"] is None
    assert data["sla_compliance_percent"] is None
    assert data["overdue_remediation_tasks"] == 0
    assert data["analyst_workload"] == []
    assert data["incident_trends_last_30_days"] == []


def test_dashboard_summary_with_incidents(client):
    user = register_user(client)

    headers = get_auth_headers(
        client,
        email=user["email"],
        password=user["password"],
    )

    from app import main
    from app.db.database import get_db

    override_db = main.app.dependency_overrides[get_db]
    db_generator = override_db()
    db = next(db_generator)

    try:
        db.add_all(
            [
                SecurityIncident(
                    incident_number=f"INC-{uuid4().hex[:10]}",
                    title="Open incident",
                    description="Test open incident",
                    status=IncidentStatus.NEW,
                    created_by_id=user["id"],
                    assigned_to_id=user["id"],
                    created_at=datetime.utcnow(),
                ),
                SecurityIncident(
                    incident_number=f"INC-{uuid4().hex[:10]}",
                    title="Resolved incident",
                    description="Test resolved incident",
                    status=IncidentStatus.RESOLVED,
                    created_by_id=user["id"],
                    assigned_to_id=user["id"],
                    created_at=datetime.utcnow() - timedelta(days=2),
                ),
                SecurityIncident(
                    incident_number=f"INC-{uuid4().hex[:10]}",
                    title="Old incident",
                    description="Outside trend window",
                    status=IncidentStatus.CLOSED,
                    created_by_id=user["id"],
                    created_at=datetime.utcnow() - timedelta(days=40),
                ),
            ]
        )
        db.commit()
    finally:
        db.close()
        db_generator.close()

    response = client.get(
        "/dashboard/summary",
        headers=headers,
    )

    assert response.status_code == 200, response.text

    data = response.json()

    assert data["total_incidents"] == 3
    assert data["open_incidents"] == 1
    assert data["resolved_incidents"] == 2

    assert data["incidents_by_status"]["new"] == 1
    assert data["incidents_by_status"]["resolved"] == 1
    assert data["incidents_by_status"]["closed"] == 1

    assert len(data["analyst_workload"]) == 1
    assert data["analyst_workload"][0]["analyst_id"] == user["id"]
    assert data["analyst_workload"][0]["assigned_incidents"] == 2

    assert len(data["incident_trends_last_30_days"]) == 2


def test_dashboard_summary_sla_compliance(client):
    headers = get_auth_headers(client)

    response = client.get(
        "/dashboard/summary",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["sla_compliance_percent"] is None
