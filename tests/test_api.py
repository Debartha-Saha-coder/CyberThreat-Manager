"""
Integration tests for the FastAPI backend using TestClient.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.connection import Base, get_db
from app.models import *  # noqa: F401,F403 — ensures all tables are registered

# ------------------------------------------------------------------ #
# Test database setup — named in-memory SQLite (shared across connections)
# ------------------------------------------------------------------ #
TEST_DB_URL = "sqlite:///file:testdb?mode=memory&cache=shared&uri=true"

test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False, "uri": True},
    echo=False,
)

TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


# Override the DB dependency
app.dependency_overrides[get_db] = override_get_db

# Patch module-level engine and SessionLocal used by lifespan startup
import app.database.connection as _db_module
import app.services.auth_service as _auth_module
_db_module.engine = test_engine  # type: ignore[assignment]
_db_module.SessionLocal = TestSession  # type: ignore[assignment]
_auth_module.SessionLocal = TestSession  # type: ignore[assignment]

# Create all tables BEFORE TestClient instantiation (lifespan runs on first request)
Base.metadata.create_all(bind=test_engine)

client = TestClient(app, raise_server_exceptions=True)


@pytest.fixture(autouse=True)
def clean_tables():
    """Clear table data between tests without dropping schema."""
    yield
    db = TestSession()
    try:
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()
    finally:
        db.close()


# ------------------------------------------------------------------ #
# Auth tests
# ------------------------------------------------------------------ #
class TestAuth:
    def test_register_user(self):
        resp = client.post("/api/v1/auth/register", json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepass123",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "test@example.com"
        assert data["role"] == "user"

    def test_register_duplicate_email(self):
        client.post("/api/v1/auth/register", json={
            "email": "dupe@example.com", "username": "user1", "password": "pass12345",
        })
        resp = client.post("/api/v1/auth/register", json={
            "email": "dupe@example.com", "username": "user2", "password": "pass12345",
        })
        assert resp.status_code == 409

    def test_login_valid(self):
        client.post("/api/v1/auth/register", json={
            "email": "login@example.com", "username": "loginuser", "password": "mypassword1",
        })
        resp = client.post("/api/v1/auth/login", json={
            "email": "login@example.com", "password": "mypassword1",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    def test_login_wrong_password(self):
        client.post("/api/v1/auth/register", json={
            "email": "wrong@example.com", "username": "wrongpw", "password": "correctpass",
        })
        resp = client.post("/api/v1/auth/login", json={
            "email": "wrong@example.com", "password": "wrongpass",
        })
        assert resp.status_code == 401

    def test_me_requires_auth(self):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def _get_token(self):
        client.post("/api/v1/auth/register", json={
            "email": "metest@example.com", "username": "meuser", "password": "testpass123",
        })
        r = client.post("/api/v1/auth/login", json={
            "email": "metest@example.com", "password": "testpass123",
        })
        return r.json()["access_token"]

    def test_me_with_auth(self):
        token = self._get_token()
        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "metest@example.com"


# ------------------------------------------------------------------ #
# Scan submission tests
# ------------------------------------------------------------------ #
class TestScans:
    def test_submit_invalid_url(self):
        resp = client.post("/api/v1/scans", json={"url": "ftp://evil.com"})
        assert resp.status_code == 400

    def test_submit_localhost_blocked(self):
        resp = client.post("/api/v1/scans", json={"url": "http://localhost/admin"})
        assert resp.status_code == 400

    def test_scan_list_empty(self):
        resp = client.get("/api/v1/scans")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_scan_not_found(self):
        resp = client.get("/api/v1/scans/99999")
        assert resp.status_code == 404


# ------------------------------------------------------------------ #
# Dashboard tests
# ------------------------------------------------------------------ #
class TestDashboard:
    def test_dashboard_stats_empty(self):
        resp = client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] == 0
        assert data["threats_detected"] == 0
        assert isinstance(data["recent_scans"], list)


# ------------------------------------------------------------------ #
# Community tests
# ------------------------------------------------------------------ #
class TestCommunity:
    def _register_and_login(self, suffix: str):
        client.post("/api/v1/auth/register", json={
            "email": f"{suffix}@example.com", "username": suffix, "password": "testpass123",
        })
        r = client.post("/api/v1/auth/login", json={
            "email": f"{suffix}@example.com", "password": "testpass123",
        })
        return r.json()["access_token"]

    def test_submit_report_requires_auth(self):
        resp = client.post("/api/v1/reports", json={
            "url": "https://phish.example.com", "category": "phishing",
            "title": "Test phishing site", "description": "This is a test phishing report for testing.",
        })
        assert resp.status_code == 401

    def test_submit_report_authenticated(self):
        token = self._register_and_login("reporter1")
        resp = client.post("/api/v1/reports", json={
            "url": "https://phish.example.com",
            "category": "phishing",
            "title": "Test phishing report",
            "description": "This is a clear phishing attempt that I identified via email.",
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201

    def test_list_reports_public(self):
        resp = client.get("/api/v1/reports")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_vote_requires_auth(self):
        resp = client.post("/api/v1/reports/1/vote", json={"vote_type": "support"})
        assert resp.status_code == 401
