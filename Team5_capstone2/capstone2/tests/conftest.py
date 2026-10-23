import os
os.environ["DATABASE_URL"]="sqlite:///./test_cloudguard.db"
os.environ["JWT_SECRET"]="test-secret"
os.environ["AZURE_MODE"]="mock"
import pytest
from fastapi.testclient import TestClient
from capstone2.database import Base, engine
from capstone2.main import app
@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.drop_all(engine); Base.metadata.create_all(engine); yield
@pytest.fixture
def client():
    with TestClient(app) as c: yield c
@pytest.fixture
def auth(client):
    r=client.post("/api/v1/auth/login",json={"username":"admin@cloudguard.local","password":"ChangeMe123!"}); return {"Authorization":f"Bearer {r.json()['access_token']}"}
