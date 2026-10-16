
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.api.auth.routes import get_current_user
from app.main import app
from app.models import UserRole
from app.models.user import User
from app.models.organization import (
    Organization,
    Department,
    Asset,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
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
from app.db.database import get_db


def register_user(client, email="search@example.com"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Search Analyst",
            "email": email,
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 201
    return response.json()


def set_actor(user_id):
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id,
        role=UserRole.SECURITY_ANALYST,
    )


@pytest.fixture
def search_data(client):
    user_data = register_user(client)
    set_actor(user_data["id"])

    # Obtain the same test database session used by the client fixture.
    db_dependency = app.dependency_overrides[get_db]
    db = next(db_dependency())

    try:
        organization = Organization(name="Search Test Org")
        db.add(organization)
        db.flush()

        department = Department(
            name="Security",
            organization_id=organization.id,
        )
        db.add(department)
        db.flush()

        asset = Asset(
            name="Search Server",
            asset_tag="SEARCH-ASSET-001",
            asset_type=AssetType.SERVER,
            criticality=AssetCriticality.HIGH,
            status=AssetStatus.ACTIVE,
            organization_id=organization.id,
            department_id=department.id,
        )
        db.add(asset)
        db.flush()

        incident = SecurityIncident(
            incident_number="INC-SEARCH-001",
            title="Suspicious login activity",
            description="Multiple failed login attempts detected",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.INVESTIGATING,
            affected_asset_id=asset.id,
            assigned_to_id=user_data["id"],
            created_by_id=user_data["id"],
        )

        alert = SecurityAlert(
            title="Malware detection",
            description="Malware detected on test server",
            source="endpoint-monitor",
            category="malware",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.NEW,
            asset_id=asset.id,
            assigned_to_id=user_data["id"],
            created_by_id=user_data["id"],
        )

        db.add_all([incident, alert])
        db.commit()

        yield {
            "user_id": user_data["id"],
            "asset_id": asset.id,
            "department_id": department.id,
        }
    finally:
        db.close()


def test_search_requires_authentication(client):
    response = client.get("/search/")
    assert response.status_code == 401


def test_search_returns_incidents_and_alerts(client, search_data):
    response = client.get("/search/")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert {item["entity_type"] for item in data["results"]} == {
        "incident",
        "alert",
    }


def test_search_incidents_only(client, search_data):
    response = client.get("/search/", params={"entity_type": "incidents"})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["results"][0]["entity_type"] == "incident"


def test_search_alerts_only(client, search_data):
    response = client.get("/search/", params={"entity_type": "alerts"})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["results"][0]["entity_type"] == "alert"


def test_search_by_text(client, search_data):
    response = client.get("/search/", params={"q": "malware"})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["results"][0]["title"] == "Malware detection"


def test_search_by_incident_number(client, search_data):
    response = client.get(
        "/search/",
        params={
            "entity_type": "incidents",
            "incident_number": "INC-SEARCH-001",
        },
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_search_by_incident_severity(client, search_data):
    response = client.get(
        "/search/",
        params={"entity_type": "incidents", "severity": "high"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_search_by_alert_severity(client, search_data):
    response = client.get(
        "/search/",
        params={"entity_type": "alerts", "severity": "critical"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1


@pytest.mark.parametrize(
    ("entity_type", "severity"),
    [
        ("incidents", "invalid"),
        ("alerts", "invalid"),
    ],
)
def test_invalid_severity_returns_no_results(
    client, search_data, entity_type, severity
):
    response = client.get(
        "/search/",
        params={"entity_type": entity_type, "severity": severity},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


@pytest.mark.parametrize(
    ("entity_type", "status"),
    [
        ("incidents", "invalid"),
        ("alerts", "invalid"),
    ],
)
def test_invalid_status_returns_no_results(
    client, search_data, entity_type, status
):
    response = client.get(
        "/search/",
        params={"entity_type": entity_type, "status": status},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_search_by_status(client, search_data):
    response = client.get(
        "/search/",
        params={"entity_type": "incidents", "status": "investigating"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_search_by_asset(client, search_data):
    response = client.get(
        "/search/",
        params={"asset_id": search_data["asset_id"]},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_search_by_analyst(client, search_data):
    response = client.get(
        "/search/",
        params={"analyst_id": search_data["user_id"]},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_search_by_department(client, search_data):
    response = client.get(
        "/search/",
        params={"department_id": search_data["department_id"]},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_search_by_date_range(client, search_data):
    start = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    end = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

    response = client.get(
        "/search/",
        params={"start_date": start, "end_date": end},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2


def test_invalid_date_range_returns_400(client, search_data):
    start = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    end = datetime.now(timezone.utc).isoformat()

    response = client.get(
        "/search/",
        params={"start_date": start, "end_date": end},
    )
    assert response.status_code == 400


def test_search_pagination(client, search_data):
    response = client.get(
        "/search/",
        params={"skip": 1, "limit": 1},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["results"]) == 1
    assert data["skip"] == 1
    assert data["limit"] == 1


@pytest.mark.parametrize(
    ("params", "expected_status"),
    [
        ({"limit": 0}, 422),
        ({"limit": 101}, 422),
        ({"skip": -1}, 422),
        ({"sort_order": "sideways"}, 422),
        ({"entity_type": "users"}, 422),
        ({"sort_by": "unknown"}, 422),
    ],
)
def test_search_query_validation(client, search_data, params, expected_status):
    response = client.get("/search/", params=params)
    assert response.status_code == expected_status


def test_search_empty_results(client, search_data):
    response = client.get(
        "/search/",
        params={"q": "text-that-does-not-exist"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0
    assert response.json()["results"] == []
