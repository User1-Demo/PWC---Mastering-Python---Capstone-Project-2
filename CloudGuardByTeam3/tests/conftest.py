import os
os.environ["DATABASE_URL"] = "sqlite:///./test_cloudguard.db"
os.environ["JWT_SECRET_KEY"] = "test-secret-key"
import pytest
from fastapi.testclient import TestClient
from cloudguard.core.security import hash_password
from cloudguard.db.base import Base
from cloudguard.db.session import SessionLocal, engine
from cloudguard.main import app
from cloudguard.models import User, UserRole
@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(engine); Base.metadata.create_all(engine)
    with SessionLocal() as db:
        db.add(User(email="admin@test.local", full_name="Admin", hashed_password=hash_password("StrongPass123!"), role=UserRole.ADMIN)); db.commit()
    yield
    Base.metadata.drop_all(engine)
@pytest.fixture
def client(): return TestClient(app)
@pytest.fixture
def token(client):
    r=client.post("/api/v1/auth/login", data={"username":"admin@test.local","password":"StrongPass123!"})
    return r.json()["access_token"]
@pytest.fixture
def headers(token): return {"Authorization": f"Bearer {token}"}
