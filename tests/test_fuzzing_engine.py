
import socket
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests

from engine.fuzzing_engine import FuzzingEngine


def make_engine(**kwargs):
    settings = {
        "target_url": "http://127.0.0.1:3000/search",
        "parameter": "q",
        "method": "GET",
        "timeout": 5,
        "delay": 0.2,
        "max_requests": 10
    }

    settings.update(kwargs)

    return FuzzingEngine(**settings)


def fake_response():
    response = SimpleNamespace(
        status_code=200,
        elapsed=SimpleNamespace(
            total_seconds=lambda: 0.15
        ),
        content=b"Local test response",
        text="Local test response",
        close=lambda: None,
    )
    response.iter_content = lambda chunk_size: iter([response.content])
    return response


def test_localhost_target_allowed():
    engine = make_engine()

    assert engine.target_url.startswith(
        "http://127.0.0.1"
    )


def test_external_target_rejected():
    with pytest.raises(ValueError):
        make_engine(
            target_url="http://example.com:80/search"
        )


def test_https_target_rejected():
    with pytest.raises(ValueError):
        make_engine(
            target_url="https://localhost:3000/search"
        )


def test_get_request(monkeypatch):
    captured = {}

    def fake_request(session, **kwargs):
        assert session.trust_env is False
        captured.update(kwargs)
        return fake_response()

    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        fake_request
    )

    engine = make_engine()
    result = engine.send_payload("hello")

    assert result["status_code"] == 200
    assert captured["method"] == "GET"
    assert captured["params"] == {"q": "hello"}
    assert captured["data"] is None
    assert captured["url"] == "http://127.0.0.1:3000/search"
    assert captured["timeout"] == 5


def test_http_request_uses_address_resolved_for_that_request(monkeypatch):
    results = [
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8080))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 8080))],
    ]
    captured = {}

    def fake_request(session, **kwargs):
        captured.update(kwargs)
        return fake_response()

    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request", fake_request
    )
    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        side_effect=results,
    ):
        engine = FuzzingEngine(
            "http://authorized.example:8080/search",
            allowed_hosts=["authorized.example"],
            delay=0.2,
        )
        engine.send_payload("input")

    assert captured["url"] == "http://1.1.1.1:8080/search"
    assert captured["headers"]["Host"] == "authorized.example:8080"


def test_post_request(monkeypatch):
    captured = {}

    def fake_request(session, **kwargs):
        assert session.trust_env is False
        captured.update(kwargs)
        return fake_response()

    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        fake_request
    )

    engine = make_engine(method="POST")
    result = engine.send_payload("hello")

    assert result["status_code"] == 200
    assert captured["method"] == "POST"
    assert captured["data"] == {"q": "hello"}
    assert captured["params"] is None


def test_request_metadata(monkeypatch):
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: fake_response()
    )

    engine = make_engine()
    result = engine.send_payload("hello")

    assert result["status_code"] == 200
    assert result["response_time"] >= 0
    assert result["response_length"] == len(
        b"Local test response"
    )
    assert result["response_text"] == "Local test response"
    assert result["error"] is None


def test_empty_payload_rejected():
    engine = make_engine()

    with pytest.raises(ValueError):
        engine.send_payload("")


def test_non_string_payload_rejected():
    engine = make_engine()

    with pytest.raises(TypeError):
        engine.send_payload(123)


def test_request_limit(monkeypatch):
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: fake_response()
    )

    engine = make_engine(max_requests=1)

    engine.send_payload("first")

    with pytest.raises(RuntimeError):
        engine.send_payload("second")


def test_network_error_recorded(monkeypatch):
    def failed_request(session, **kwargs):
        raise requests.Timeout("Request timed out")

    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        failed_request
    )

    engine = make_engine()
    result = engine.send_payload("hello")

    assert result["status_code"] is None
    assert result["response_time"] >= 0
    assert result["response_length"] is None
    assert result["response_text"] is None
    assert result["error"] == "Timeout"


def test_redirects_disabled(monkeypatch):
    captured = {}

    def fake_request(session, **kwargs):
        assert session.trust_env is False
        captured.update(kwargs)
        return fake_response()

    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        fake_request
    )

    engine = make_engine()
    engine.send_payload("hello")

    assert captured["allow_redirects"] is False
    assert captured["stream"] is True
    assert captured["proxies"] == {}


def test_request_count_increases(monkeypatch):
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: fake_response()
    )

    engine = make_engine()

    engine.send_payload("first")
    engine.send_payload("second")

    assert engine.request_count == 2


def test_run_preserves_safe_payload_metadata(monkeypatch):
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: fake_response()
    )

    result = make_engine().run(
        [
            {
                "payload": "hello",
                "payload_id": "payload-1",
                "strategy": "grammar",
                "original_payload": "hello",
                "ignored": "not persisted",
            }
        ]
    )[0]

    assert result["payload_id"] == "payload-1"
    assert result["strategy"] == "grammar"
    assert result["original_payload"] == "hello"
    assert "ignored" not in result


def test_invalid_metadata_is_rejected_before_request(monkeypatch):
    called = False

    def fake_request(session, **kwargs):
        nonlocal called
        called = True
        return fake_response()

    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request", fake_request
    )

    with pytest.raises(TypeError, match="metadata"):
        make_engine().send_payload("hello", metadata=123)

    assert called is False


def test_response_body_is_limited(monkeypatch):
    response = fake_response()
    response.content = b"0123456789"
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: response
    )

    result = make_engine(max_response_bytes=5).send_payload("hello")

    assert result["response_length"] == 5
    assert result["response_text"] == "01234"
    assert result["response_truncated"] is True


def test_streamed_response_body_is_stopped_at_limit(monkeypatch):
    response = fake_response()
    yielded = []
    closed = []

    def chunks(chunk_size):
        for chunk in (b"01234", b"56789", b"never-read"):
            yielded.append(chunk)
            yield chunk

    response.iter_content = chunks
    response.close = lambda: closed.append(True)
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: response
    )

    result = make_engine(max_response_bytes=5).send_payload("hello")

    assert result["response_length"] == 5
    assert result["response_truncated"] is True
    assert len(yielded) == 2
    assert closed == [True]


def test_total_response_deadline_closes_response(monkeypatch):
    response = fake_response()
    closed = []
    response.close = lambda: closed.append(True)
    monkeypatch.setattr(
        "engine.fuzzing_engine.requests.Session.request",
        lambda session, **kwargs: response
    )
    engine = make_engine(timeout=1)
    clock_values = iter([0.0, 0.0, 0.0, 2.0, 2.0])
    monkeypatch.setattr(
        "engine.fuzzing_engine.time.monotonic",
        lambda: next(clock_values),
    )

    result = engine.send_payload("hello")

    assert result["error"] == "Timeout"
    assert result["status_code"] is None
    assert closed == [True]


def test_rate_limiter_enforces_configured_minimum_delay(monkeypatch):
    engine = make_engine(delay=0.5)
    clock_values = iter([0.0, 0.0, 0.1, 0.5])
    waits = []
    monkeypatch.setattr(
        "engine.fuzzing_engine.time.monotonic",
        lambda: next(clock_values),
    )
    monkeypatch.setattr(
        engine._cancel_event,
        "wait",
        lambda delay: waits.append(delay) or False,
    )

    engine._reserve_request()
    engine._reserve_request()

    assert waits == pytest.approx([0.4])
    assert engine.request_count == 2


def test_cancel_prevents_next_request():
    engine = make_engine()
    engine.cancel()

    with pytest.raises(RuntimeError, match="cancelled"):
        engine.send_payload("hello")


def test_run_cancellation_preserves_completed_results(monkeypatch):
    from engine.fuzzing_engine import ScanCancelled

    engine = make_engine()
    sent = []

    def send_and_cancel(payload, metadata=None):
        sent.append(payload)
        engine.cancel()
        return {"payload": payload, "error": None}

    monkeypatch.setattr(engine, "send_payload", send_and_cancel)

    with pytest.raises(ScanCancelled) as error:
        engine.run(["first", "not-sent"])

    assert error.value.results == [{"payload": "first", "error": None}]
    assert sent == ["first"]


def test_explicit_allowlist_does_not_skip_private_address_policy():
    from unittest.mock import patch

    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("127.0.0.1", 3000))
        ],
    ):
        with pytest.raises(ValueError, match="non-public address"):
            FuzzingEngine(
                target_url="http://authorized.example:3000/",
                allowed_hosts=["authorized.example"],
            )
