import pytest
import os
os.environ["UDP_PORT"] = "5515"
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import app
from common.database import get_db, Base
from common.models import UserRow
from auth.dependencies import get_current_user
from auth.security import hash_password

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_ulpf.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

class FakeUser:
    username = "testuser"

def override_get_current_user():
    return FakeUser()

@pytest.fixture(scope="session")
def test_client():
    with TestClient(app) as client:
        yield client

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(autouse=True)
def auth_bypass(request):
    if request.node.get_closest_marker("no_auth_override"):
        yield
        return
    app.dependency_overrides[get_current_user] = override_get_current_user
    yield
    app.dependency_overrides.pop(get_current_user, None)

@pytest.fixture
def seeded_user(setup_db):
    db = TestingSessionLocal()
    db.add(UserRow(username="admin", hashed_password=hash_password("changeme123")))
    db.commit()
    db.close()

@pytest.fixture
def auth_token(test_client, seeded_user):
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "changeme123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
