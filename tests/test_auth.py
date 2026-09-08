from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from auth.jwt import ALGORITHM, SECRET_KEY


pytestmark = pytest.mark.no_auth_override


def test_login_success(test_client, seeded_user):
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "changeme123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(test_client, seeded_user):
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_protected_endpoint_without_token(test_client, seeded_user):
    response = test_client.get("/api/v1/events")
    assert response.status_code == 401


def test_protected_endpoint_with_valid_token(test_client, seeded_user, auth_headers):
    response = test_client.get("/api/v1/events", headers=auth_headers)
    assert response.status_code == 200


def test_auth_me(test_client, seeded_user, auth_headers):
    response = test_client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["username"] == "admin"


def test_expired_token_rejected(test_client, seeded_user):
    expire = datetime.now(timezone.utc) - timedelta(hours=1)
    token = jwt.encode({"sub": "admin", "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    response = test_client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_malformed_token_rejected(test_client, seeded_user):
    response = test_client.get(
        "/api/v1/events",
        headers={"Authorization": "Bearer not-a-valid-token"},
    )
    assert response.status_code == 401
