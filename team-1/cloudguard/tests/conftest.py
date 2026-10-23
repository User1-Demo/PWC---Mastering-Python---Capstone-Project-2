import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cloudguard.database import Base, get_db
from cloudguard.main import app
from cloudguard import models, security

TEST_DB_URL = "sqlite://"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine)


@pytest.fixture()
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session, monkeypatch):
    def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db

    # Worker modules call SessionLocal() directly (bypassing FastAPI's
    # dependency injection). During tests, point them at the SAME
    # in-memory test database instead of the real production database.
    monkeypatch.setattr("cloudguard.workers.scan_worker.SessionLocal", TestingSessionLocal)
    monkeypatch.setattr("cloudguard.workers.remediation_worker.SessionLocal", TestingSessionLocal)

    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_user(db_session):
    user = models.User(email="admin@test.com", hashed_password=security.hash_password("pass123"),
                        role=models.RoleEnum.ADMIN)
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture()
def security_officer(db_session):
    user = models.User(email="secoff@test.com", hashed_password=security.hash_password("pass123"),
                        role=models.RoleEnum.SECURITY_OFFICER)
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture()
def auth_header(admin_user):
    token = security.create_access_token(admin_user.id, admin_user.role.value)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def secoff_header(security_officer):
    token = security.create_access_token(security_officer.id, security_officer.role.value)
    return {"Authorization": f"Bearer {token}"}