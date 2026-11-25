def test_root(client):
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert "version" in data

def test_status(client):
    response = client.get("/status")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["app_version"] == "1.0.0"