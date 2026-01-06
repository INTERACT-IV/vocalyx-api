"""Tests basiques de l’API FastAPI (endpoints simples)."""

from fastapi.testclient import TestClient

from app import app


client = TestClient(app)


def test_root_endpoint_returns_service_info():
    response = client.get("/")
    assert response.status_code == 200

    data = response.json()
    assert data.get("service") == "vocalyx-api"
    assert data.get("status") == "operational"


def test_health_check_endpoint_ok():
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data.get("status") == "healthy"
    assert data.get("service") == "vocalyx-api"


