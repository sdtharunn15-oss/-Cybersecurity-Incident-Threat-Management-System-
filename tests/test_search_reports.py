def test_search_requires_authentication(client):
    response = client.get("/search/")
    assert response.status_code == 401


def test_report_summary_requires_authentication(client):
    response = client.get("/reports/summary")
    assert response.status_code == 401


def test_incident_csv_requires_authentication(client):
    response = client.get("/reports/incidents/csv")
    assert response.status_code == 401


def test_health_endpoint_still_works(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}