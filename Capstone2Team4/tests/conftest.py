import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db, initialize_database
from app.main import app
from app.models import User
from app.security import hash_password


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    initialize_database(engine)
    monkeypatch.setattr("app.services.scans.SessionLocal", TestingSession)
    monkeypatch.setattr("app.services.remediation.SessionLocal", TestingSession)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestingSession() as db:
        db.add(
            User(
                email="admin@test.local",
                password_hash=hash_password("AdminPassword123!"),
                role="admin",
            )
        )
        db.commit()
    with TestClient(app) as test_client:
        yield test_client, TestingSession
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def admin_headers(client):
    test_client, _ = client
    response = test_client.post(
        "/api/v1/auth/login",
        json={"email": "admin@test.local", "password": "AdminPassword123!"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
