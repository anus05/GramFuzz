import socket
import threading
from unittest.mock import patch

import pytest

from engine.scope_validator import ScopeValidationError, ScopeValidator


def test_localhost_is_pinned_to_loopback_address():
    validator = ScopeValidator("http://localhost:3000/search?q=1")

    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 3000))
        ],
    ):
        assert validator.validate_and_pin() == (
            "http://127.0.0.1:3000/search?q=1"
        )


def test_unlisted_host_is_rejected():
    with pytest.raises(ScopeValidationError, match="Unauthorized target host"):
        ScopeValidator("http://example.com:8080")


def test_credentials_are_rejected_even_when_empty():
    with pytest.raises(ScopeValidationError, match="Credentials"):
        ScopeValidator("http://@localhost:3000")


def test_invalid_port_is_rejected():
    with pytest.raises(ScopeValidationError, match="Invalid target URL"):
        ScopeValidator("http://localhost:99999")


def test_allowlisted_host_must_resolve_to_public_ip_by_default():
    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 8080))
        ],
    ):
        with pytest.raises(ScopeValidationError, match="non-public address"):
            ScopeValidator(
                "http://authorized.example:8080",
                allowed_hosts=["authorized.example"],
            )


def test_explicit_private_address_authorization_pins_address():
    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 8080))
        ],
    ):
        validator = ScopeValidator(
            "http://authorized.example:8080",
            allowed_hosts=["authorized.example"],
            allow_private_addresses=True,
        )
        assert validator.validate_and_pin() == "http://192.168.1.20:8080"


def test_localhost_cannot_resolve_to_a_public_address():
    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8080))
        ],
    ):
        with pytest.raises(ScopeValidationError, match="outside loopback"):
            ScopeValidator("http://localhost:8080")


@pytest.mark.parametrize(
    "address",
    ["169.254.169.254", "10.0.0.5", "192.168.1.1"],
)
def test_private_and_metadata_addresses_require_explicit_permission(address):
    with patch(
        "engine.scope_validator.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 8080))
        ],
    ):
        with pytest.raises(ScopeValidationError, match="non-public address"):
            ScopeValidator(
                "http://authorized.example:8080",
                allowed_hosts=["authorized.example"],
            )


def test_dns_resolution_has_a_deadline_and_fails_closed():
    release_resolver = threading.Event()
    resolver_finished = threading.Event()

    def blocked_resolver(host, port, type):
        release_resolver.wait(timeout=2)
        resolver_finished.set()
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ]

    with pytest.raises(ScopeValidationError, match="exceeded 0.1 seconds"):
        ScopeValidator(
            "http://authorized.example:8080",
            allowed_hosts=["authorized.example"],
            dns_timeout=0.1,
            resolver=blocked_resolver,
        )

    release_resolver.set()
    assert resolver_finished.wait(timeout=1)


def test_dns_timeout_setting_is_bounded():
    with pytest.raises(ScopeValidationError, match="DNS timeout"):
        ScopeValidator("http://127.0.0.1:8080", dns_timeout=0)
