import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.auth import get_current_admin
from api.database import Base
from api.dependencies import get_db
from api.main import app
from api.models.alert import Alert
from api.routers import analyze as analyze_router
from api.routers import capture as capture_router
from api.services import capture_service
from api.services.validation import list_interfaces, validate_interface
from fastapi import HTTPException


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def authed_client(client, db_session):
    app.dependency_overrides[get_current_admin] = lambda: "admin"
    app.dependency_overrides[get_db] = lambda: db_session
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def a_real_interface():
    return sorted(list_interfaces())[0]


def test_validate_interface_rejects_unknown_and_option_like_names(a_real_interface):
    assert validate_interface(a_real_interface) == a_real_interface
    for bad in ["--help", "-c", "no_such_if0", "lo; rm -rf /", ""]:
        with pytest.raises(HTTPException) as exc:
            validate_interface(bad)
        assert exc.value.status_code == 422


def test_capture_start_ignores_client_supplied_path(authed_client, a_real_interface, monkeypatch):
    seen = {}

    async def fake_capture(interface, duration, output_path, stop_event=None):
        seen["path"] = output_path

    monkeypatch.setattr(capture_router, "run_live_capture", fake_capture)
    capture_router._capture_running = False

    resp = authed_client.post(
        "/capture/start",
        json={"interface": a_real_interface, "duration_seconds": 5, "output_path": "../../.env"},
    )
    assert resp.status_code == 202
    assert resp.json()["output"].startswith(str(capture_service.CAPTURE_DIR))
    assert ".env" not in resp.json()["output"]


def test_capture_start_rejects_bad_interface_and_duration(authed_client, a_real_interface):
    capture_router._capture_running = False
    r = authed_client.post("/capture/start", json={"interface": "--help"})
    assert r.status_code == 422
    r = authed_client.post(
        "/capture/start", json={"interface": a_real_interface, "duration_seconds": 100000}
    )
    assert r.status_code == 422


def test_unsafe_output_path_is_refused_by_service():
    for bad in ["../../.env", "/etc/passwd", "data/capture.csv"]:
        with pytest.raises(RuntimeError):
            capture_service.ensure_safe_output_path(bad)


def _fake_analyze(monkeypatch, result):
    async def fake_capture(*args, **kwargs):
        return None

    monkeypatch.setattr(analyze_router, "run_live_capture", fake_capture)
    monkeypatch.setattr(analyze_router, "analyze_capture", lambda path, rf: result)
    monkeypatch.setattr(analyze_router.registry, "get_random_forest", lambda: object())


def test_benign_result_is_not_stored_as_alert(authed_client, db_session, a_real_interface, monkeypatch):
    _fake_analyze(monkeypatch, {
        "prediction": "BENIGN", "confidence": 0.1, "severity": "normal",
        "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "protocol": "6",
        "flows_analyzed": 20,
    })
    resp = authed_client.post("/analyze/", json={"interface": a_real_interface})
    assert resp.status_code == 200
    assert db_session.query(Alert).count() == 0


def test_attack_result_is_stored_as_alert(authed_client, db_session, a_real_interface, monkeypatch):
    _fake_analyze(monkeypatch, {
        "prediction": "ATTACK", "confidence": 0.83, "severity": "anomaly",
        "source_ip": "172.17.0.1", "destination_ip": "172.17.0.2", "protocol": "6",
        "flows_analyzed": 495,
    })
    resp = authed_client.post("/analyze/", json={"interface": a_real_interface})
    assert resp.status_code == 200
    assert db_session.query(Alert).count() == 1


def test_token_endpoint_is_rate_limited(client):
    codes = [
        client.post("/token", data={"username": "nobody", "password": "wrong"}).status_code
        for _ in range(7)
    ]
    assert codes[:5] == [401] * 5
    assert 429 in codes
