from fastapi.testclient import TestClient

from cloudguard.main import app

client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "cloudguard-api",
        "version": "0.1.0",
    }