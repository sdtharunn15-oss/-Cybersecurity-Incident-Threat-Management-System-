
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.main import app
from app.db.database import get_db
from app.api.auth.routes import get_current_user
from app.models.user import UserRole
from app.models.alert import SecurityAlert, AlertSeverity
from app.models.incident import SecurityIncident, IncidentStatus
from app.models.organization import (
    Organization,
    Department,
    Asset,
    AssetType,
    AssetCriticality,
    AssetStatus,
)


def register_user(client, email="correlation-user@example.com"):
    response = client.post(
        "/auth/register",
        json={
            "full_name": "Correlation Test User",
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
    db_dependency = app.dependency_overrides[get_db]
    return next(db_dependency())


def create_asset():
    db = get_test_db()
    try:
        organization = Organization(
            name="Correlation Test Organization",
            description="Test organization",
        )
        db.add(organization)
        db.flush()

        department = Department(
            name="Correlation Security",
            organization_id=organization.id,
        )
        db.add(department)
        db.flush()

        asset = Asset(
            name="Correlation Test Server",
            asset_tag="CORRELATION-ASSET-001",
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


def create_incident(client, title="Suspicious login activity", **overrides):
    payload = {
        "title": title,
        "description": "Security incident created for correlation testing.",
        "severity": "medium",
    }
    payload.update(overrides)

    response = client.post("/incidents", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def create_alert(
    user_id,
    asset_id,
    title="Repeated login failure",
    source="Test SIEM",
    category="Authentication",
    occurred_at=None,
):
    db = get_test_db()
    try:
        alert = SecurityAlert(
            title=title,
            description="Alert created for correlation testing.",
            source=source,
            category=category,
            severity=AlertSeverity.HIGH,
            asset_id=asset_id,
            created_by_id=user_id,
            occurred_at=occurred_at or datetime.now(timezone.utc),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert.id
    finally:
        db.close()


def set_incident_fields(incident_id, **fields):
    db = get_test_db()
    try:
        incident = db.get(SecurityIncident, incident_id)
        for field, value in fields.items():
            setattr(incident, field, value)
        db.commit()
    finally:
        db.close()


def test_repeated_alerts_groups_matching_alerts(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    first_id = create_alert(
        user_id, asset_id, title="  Failed Login  ", source=" SIEM ",
        category=" Authentication "
    )
    second_id = create_alert(
        user_id, asset_id, title="failed login", source="siem",
        category="authentication"
    )

    response = client.get("/correlation/repeated-alerts")

    assert response.status_code == 200
    data = response.json()
    assert data["groups_found"] == 1
    assert data["groups"][0]["count"] == 2
    assert set(data["groups"][0]["alert_ids"]) == {first_id, second_id}


def test_repeated_alerts_ignores_alerts_below_minimum_count(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    create_alert(user_id, asset_id)

    response = client.get("/correlation/repeated-alerts?min_count=2")

    assert response.status_code == 200
    assert response.json()["groups_found"] == 0


def test_repeated_alerts_rejects_invalid_query_values(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/correlation/repeated-alerts?hours=0")

    assert response.status_code == 422


def test_repeated_alerts_rejects_inactive_user(client):
    user_id = register_user(client)
    set_actor(user_id, is_active=False)

    response = client.get("/correlation/repeated-alerts")

    assert response.status_code == 403


def test_link_alerts_to_incident_success_and_history(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    incident = create_incident(client)
    alert_id = create_alert(user_id, asset_id)

    response = client.post(
        f"/correlation/incidents/{incident['id']}/alerts",
        json={"alert_ids": [alert_id]},
    )

    assert response.status_code == 200
    assert response.json()["linked_alert_ids"] == [alert_id]
    assert response.json()["total_linked_alerts"] == 1

    history = client.get(
        f"/correlation/history?incident_id={incident['id']}"
    )
    assert history.status_code == 200
    assert any(item["action"] == "alert_linked" for item in history.json())


def test_link_alerts_reports_already_linked_alert(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    incident = create_incident(client)
    alert_id = create_alert(user_id, asset_id)

    first = client.post(
        f"/correlation/incidents/{incident['id']}/alerts",
        json={"alert_ids": [alert_id]},
    )
    assert first.status_code == 200

    second = client.post(
        f"/correlation/incidents/{incident['id']}/alerts",
        json={"alert_ids": [alert_id]},
    )

    assert second.status_code == 200
    assert second.json()["linked_alert_ids"] == []
    assert second.json()["already_linked_alert_ids"] == [alert_id]


def test_link_alerts_rejects_missing_alert(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.post(
        f"/correlation/incidents/{incident['id']}/alerts",
        json={"alert_ids": [99999]},
    )

    assert response.status_code == 404


def test_link_alerts_rejects_missing_incident(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.post(
        "/correlation/incidents/99999/alerts",
        json={"alert_ids": [1]},
    )

    assert response.status_code == 404


def test_link_alerts_rejects_closed_incident(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()
    incident = create_incident(client)
    set_incident_fields(
        incident["id"],
        status=IncidentStatus.CLOSED,
    )
    alert_id = create_alert(user_id, asset_id)

    response = client.post(
        f"/correlation/incidents/{incident['id']}/alerts",
        json={"alert_ids": [alert_id]},
    )

    assert response.status_code == 400



def test_link_alerts_rejects_auditor_role(client):
    user_id = register_user(client)

    # Create the incident while the user has permission.
    set_actor(user_id, role=UserRole.SECURITY_ANALYST)
    incident = create_incident(client)

    # Switch to auditor before testing the correlation permission.
    set_actor(user_id, role=UserRole.AUDITOR)

    response = client.post(
        f"/correlation/incidents/{incident['id']}/alerts",
        json={"alert_ids": [1]},
    )

    assert response.status_code == 403
    assert "permission to correlate" in response.json()["detail"]


def test_possible_duplicate_incidents_groups_normalized_titles(client):
    user_id = register_user(client)
    set_actor(user_id)
    asset_id = create_asset()

    first = create_incident(client, title=" Suspicious   Login ")
    second = create_incident(client, title="suspicious login")

    set_incident_fields(first["id"], affected_asset_id=asset_id)
    set_incident_fields(second["id"], affected_asset_id=asset_id)

    response = client.get("/correlation/possible-duplicate-incidents")

    assert response.status_code == 200
    data = response.json()
    assert data["groups_found"] == 1
    assert data["groups"][0]["normalized_title"] == "suspicious login"
    assert data["groups"][0]["count"] == 2
    assert data["groups"][0]["review_required"] is True


def test_possible_duplicate_incidents_ignores_incidents_without_asset(client):
    user_id = register_user(client)
    set_actor(user_id)

    create_incident(client, title="Same incident")
    create_incident(client, title="Same incident")

    response = client.get("/correlation/possible-duplicate-incidents")

    assert response.status_code == 200
    assert response.json()["groups_found"] == 0


def test_link_related_incidents_success_and_duplicate_link(client):
    user_id = register_user(client)
    set_actor(user_id)
    first = create_incident(client, title="First incident")
    second = create_incident(client, title="Related incident")

    url = (
        f"/correlation/incidents/{first['id']}/related/"
        f"{second['id']}"
    )

    response = client.post(url)
    assert response.status_code == 200
    assert response.json()["message"] == "Related incidents linked."

    duplicate = client.post(url)
    assert duplicate.status_code == 200
    assert duplicate.json()["message"] == "These incidents are already linked."


def test_link_related_incidents_rejects_self_link(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.post(
        f"/correlation/incidents/{incident['id']}/related/{incident['id']}"
    )

    assert response.status_code == 400


def test_link_related_incidents_rejects_missing_incident(client):
    user_id = register_user(client)
    set_actor(user_id)
    incident = create_incident(client)

    response = client.post(
        f"/correlation/incidents/{incident['id']}/related/99999"
    )

    assert response.status_code == 404


def test_list_related_incidents_returns_linked_records(client):
    user_id = register_user(client)
    set_actor(user_id)
    first = create_incident(client, title="Primary incident")
    second = create_incident(client, title="Related incident")

    link_response = client.post(
        f"/correlation/incidents/{first['id']}/related/{second['id']}"
    )
    assert link_response.status_code == 200

    response = client.get(
        f"/correlation/incidents/{first['id']}/related"
    )

    assert response.status_code == 200
    assert response.json()["incident_id"] == first["id"]
    assert len(response.json()["related_incidents"]) == 1
    assert response.json()["related_incidents"][0]["id"] == second["id"]


def test_list_related_incidents_for_missing_incident(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/correlation/incidents/99999/related")

    assert response.status_code == 404


def test_correlation_history_supports_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)
    first = create_incident(client, title="First incident")
    second = create_incident(client, title="Second incident")

    response_one = client.post(
        f"/correlation/incidents/{first['id']}/related/{second['id']}"
    )
    response_two = client.post(
        f"/correlation/incidents/{second['id']}/related/{first['id']}"
    )
    assert response_one.status_code == 200
    assert response_two.status_code == 200

    page_one = client.get("/correlation/history?page=1&page_size=1")
    page_two = client.get("/correlation/history?page=2&page_size=1")

    assert page_one.status_code == 200
    assert page_two.status_code == 200
    assert len(page_one.json()) == 1
    assert len(page_two.json()) == 1
    assert page_one.json()[0]["id"] != page_two.json()[0]["id"]


def test_correlation_history_rejects_invalid_pagination(client):
    user_id = register_user(client)
    set_actor(user_id)

    response = client.get("/correlation/history?page=0")

    assert response.status_code == 422


def test_correlation_endpoints_require_authentication(client):
    response = client.get("/correlation/repeated-alerts")

    assert response.status_code == 401
