
import csv
import io
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.incident import (
    SecurityIncident,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.alert import (
    SecurityAlert,
    AlertSeverity,
    AlertStatus,
)
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.models.remediation import (
    RemediationTask,
    RemediationPriority,
    RemediationStatus,
)


def register_user(client):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Reports Test User",
            "email": f"reports_{uuid4().hex[:10]}@example.com",
            "password": "StrongPassword123!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def set_actor(user_id, role=UserRole.SECURITY_ANALYST):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=role,
        is_active=True,
    )


def get_test_db():
    db_generator = app.dependency_overrides[get_db]()
    return next(db_generator)


def create_asset(db, user_id):
    from app.models.organization import (
        Organization,
        Department,
        Asset,
        AssetType,
        AssetCriticality,
    )

    organization = Organization(
        name=f"Reports Org {uuid4().hex[:8]}",
        description="Organization for report tests",
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)

    department = Department(
        name=f"Reports Department {uuid4().hex[:8]}",
        description="Department for report tests",
        organization_id=organization.id,
    )
    db.add(department)
    db.commit()
    db.refresh(department)

    asset = Asset(
        name=f"Reports Asset {uuid4().hex[:8]}",
        asset_tag=f"RPT-ASSET-{uuid4().hex[:10]}",
        description="Asset for report tests",
        asset_type=AssetType.SERVER,
        criticality=AssetCriticality.HIGH,
        organization_id=organization.id,
        department_id=department.id,
        owner_id=user_id,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


def create_incident(
    db,
    user_id,
    title="Reports incident",
    created_at=None,
):
    incident = SecurityIncident(
        incident_number=f"RPT-{uuid4().hex[:10].upper()}",
        title=title,
        description="Incident for report tests",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.NEW,
        created_by_id=user_id,
    )

    if created_at is not None:
        incident.created_at = created_at

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


def create_alert(
    db,
    user_id,
    asset_id,
    title="Reports alert",
    created_at=None,
):
    alert = SecurityAlert(
        title=title,
        description="Alert for report tests",
        source="unit-test",
        category="test",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.NEW,
        asset_id=asset_id,
        created_by_id=user_id,
    )

    if created_at is not None:
        alert.created_at = created_at

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert


def create_vulnerability(
    db,
    user_id,
    asset_id,
    title="Reports vulnerability",
    created_at=None,
):
    vulnerability = Vulnerability(
        title=title,
        description="Vulnerability for report tests",
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=8.0,
        affected_asset_id=asset_id,
        remediation_recommendation="Apply security updates",
        status=VulnerabilityStatus.OPEN,
        created_by_id=user_id,
    )

    if created_at is not None:
        vulnerability.created_at = created_at

    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)

    return vulnerability


def create_remediation(
    db,
    user_id,
    vulnerability_id,
    title="Reports remediation",
    created_at=None,
):
    task = RemediationTask(
        title=title,
        description="Remediation for report tests",
        vulnerability_id=vulnerability_id,
        created_by_id=user_id,
        priority=RemediationPriority.HIGH,
        status=RemediationStatus.OPEN,
    )

    if created_at is not None:
        task.created_at = created_at

    db.add(task)
    db.commit()
    db.refresh(task)

    return task


@pytest.fixture()
def report_context(client):
    user_id = register_user(client)
    set_actor(user_id)
    db = get_test_db()

    try:
        asset = create_asset(db, user_id)
        incident = create_incident(db, user_id)
        alert = create_alert(db, user_id, asset.id)
        vulnerability = create_vulnerability(db, user_id, asset.id)
        remediation = create_remediation(
            db,
            user_id,
            vulnerability.id,
        )

        yield {
            "user_id": user_id,
            "asset_id": asset.id,
            "incident_id": incident.id,
            "alert_id": alert.id,
            "vulnerability_id": vulnerability.id,
            "remediation_id": remediation.id,
        }
    finally:
        db.close()


def parse_csv(response):
    return list(csv.DictReader(io.StringIO(response.text)))


def test_report_summary_empty_database(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/reports/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["incidents"] == 0
    assert data["alerts"] == 0
    assert data["vulnerabilities"] == 0
    assert data["remediations"] == 0
    assert data["start_date"] is None
    assert data["end_date"] is None


def test_report_summary_counts_all_report_types(client, report_context):
    response = client.get("/reports/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["incidents"] == 1
    assert data["alerts"] == 1
    assert data["vulnerabilities"] == 1
    assert data["remediations"] == 1


def test_report_summary_includes_date_parameters(client, report_context):
    response = client.get(
        "/reports/summary",
        params={
            "start_date": "2020-01-01T00:00:00",
            "end_date": "2035-01-01T00:00:00",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["incidents"] == 1
    assert data["alerts"] == 1
    assert data["vulnerabilities"] == 1
    assert data["remediations"] == 1
    assert data["start_date"] is not None
    assert data["end_date"] is not None


def test_report_summary_rejects_reversed_date_range(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get(
        "/reports/summary",
        params={
            "start_date": "2030-01-01T00:00:00",
            "end_date": "2020-01-01T00:00:00",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "start_date must be before or equal to end_date"
    )


def test_report_summary_rejects_invalid_datetime(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get(
        "/reports/summary",
        params={"start_date": "not-a-date"},
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("report_type", "expected_filename"),
    [
        ("incidents", "incidents_report.csv"),
        ("alerts", "alerts_report.csv"),
        ("vulnerabilities", "vulnerabilities_report.csv"),
        ("remediations", "remediations_report.csv"),
    ],
)
def test_csv_report_success(
    client,
    report_context,
    report_type,
    expected_filename,
):
    response = client.get(f"/reports/{report_type}/csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert expected_filename in response.headers["content-disposition"]

    rows = parse_csv(response)
    assert len(rows) == 1


@pytest.mark.parametrize(
    ("report_type", "expected_column", "expected_value"),
    [
        ("incidents", "title", "Reports incident"),
        ("alerts", "title", "Reports alert"),
        ("vulnerabilities", "title", "Reports vulnerability"),
        ("remediations", "title", "Reports remediation"),
    ],
)
def test_csv_report_contains_expected_record(
    client,
    report_context,
    report_type,
    expected_column,
    expected_value,
):
    response = client.get(f"/reports/{report_type}/csv")

    assert response.status_code == 200
    rows = parse_csv(response)
    assert rows[0][expected_column] == expected_value


def test_incident_csv_serializes_enum_values(client, report_context):
    response = client.get("/reports/incidents/csv")

    assert response.status_code == 200
    row = parse_csv(response)[0]
    assert row["severity"] == "high"
    assert row["status"] == "new"


def test_csv_report_empty_results(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/reports/incidents/csv")

    assert response.status_code == 200
    assert parse_csv(response) == []
    assert "incident_number" in response.text.splitlines()[0]


@pytest.mark.parametrize(
    "report_type",
    ["incidents", "alerts", "vulnerabilities", "remediations"],
)
def test_csv_report_date_filter_returns_matching_records(
    client,
    report_context,
    report_type,
):
    response = client.get(
        f"/reports/{report_type}/csv",
        params={
            "start_date": "2020-01-01T00:00:00",
            "end_date": "2035-01-01T00:00:00",
        },
    )

    assert response.status_code == 200
    assert len(parse_csv(response)) == 1


@pytest.mark.parametrize(
    "url",
    [
        "/reports/incidents/csv",
        "/reports/alerts/csv",
        "/reports/vulnerabilities/csv",
        "/reports/remediations/csv",
    ],
)
def test_csv_rejects_reversed_date_range(client, url):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get(
        url,
        params={
            "start_date": "2030-01-01T00:00:00",
            "end_date": "2020-01-01T00:00:00",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "start_date must be before or equal to end_date"
    )


def test_csv_rejects_invalid_datetime(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get(
        "/reports/incidents/csv",
        params={"start_date": "invalid-date"},
    )

    assert response.status_code == 422


def test_csv_rejects_unsupported_report_type(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/reports/unknown/csv")

    assert response.status_code == 422


def test_report_summary_start_date_only(client, report_context):
    response = client.get(
        "/reports/summary",
        params={"start_date": "2020-01-01T00:00:00"},
    )

    assert response.status_code == 200
    assert response.json()["incidents"] == 1
    assert response.json()["end_date"] is None


def test_report_summary_end_date_only(client, report_context):
    response = client.get(
        "/reports/summary",
        params={"end_date": "2035-01-01T00:00:00"},
    )

    assert response.status_code == 200
    assert response.json()["incidents"] == 1
    assert response.json()["start_date"] is None


def test_csv_report_start_date_only(client, report_context):
    response = client.get(
        "/reports/incidents/csv",
        params={"start_date": "2020-01-01T00:00:00"},
    )

    assert response.status_code == 200
    assert len(parse_csv(response)) == 1


def test_csv_report_end_date_only(client, report_context):
    response = client.get(
        "/reports/incidents/csv",
        params={"end_date": "2035-01-01T00:00:00"},
    )

    assert response.status_code == 200
    assert len(parse_csv(response)) == 1
