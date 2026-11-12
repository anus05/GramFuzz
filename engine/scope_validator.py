"""Target URL validation and DNS-pinned connection preparation."""

import ipaddress
import queue
import socket
import threading
from collections.abc import Sequence
from urllib.parse import urlsplit, urlunsplit


_DNS_RESOLUTION_LOCK = threading.Lock()


class ScopeValidationError(ValueError):
    """Raised when a target is outside the configured authorization scope."""


class ScopeValidator:
    """Validate an HTTP target and pin each request to a validated IP address."""

    DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

    def __init__(
        self,
        target_url,
        allowed_hosts=None,
        allow_private_addresses=False,
        dns_timeout=3.0,
        resolver=None,
    ):
        self.target_url = target_url
        self.allowed_hosts = set(self.DEFAULT_ALLOWED_HOSTS)
        if allowed_hosts is not None:
            if isinstance(allowed_hosts, str) or not isinstance(
                allowed_hosts, Sequence
            ):
                raise ScopeValidationError(
                    "allowed_hosts must be a sequence of hostnames."
                )
            for host in allowed_hosts:
                if not isinstance(host, str) or not host.strip():
                    raise ScopeValidationError(
                        "Allowed hosts must be non-empty strings."
                    )
                self.allowed_hosts.add(self._normalize_host(host))
        self.allow_private_addresses = allow_private_addresses
        if not isinstance(allow_private_addresses, bool):
            raise ScopeValidationError(
                "allow_private_addresses must be a boolean."
            )
        if (
            not isinstance(dns_timeout, (int, float))
            or isinstance(dns_timeout, bool)
            or not 0.1 <= dns_timeout <= 15
        ):
            raise ScopeValidationError(
                "DNS timeout must be between 0.1 and 15 seconds."
            )
        self.dns_timeout = float(dns_timeout)
        self._resolver = resolver or socket.getaddrinfo
        self._resolution_lock = threading.Lock()
        self._resolution_timed_out = False

        self._parsed = self._parse_target(target_url)
        self.validate_and_pin()

    def _parse_target(self, target_url):
        if not isinstance(target_url, str) or not target_url:
            raise ScopeValidationError("Target URL must be a non-empty string.")

        try:
            parsed = urlsplit(target_url)
            port = parsed.port
            hostname = parsed.hostname
        except ValueError as error:
            raise ScopeValidationError(f"Invalid target URL: {error}") from error

        if parsed.scheme.lower() != "http":
            raise ScopeValidationError("Only HTTP targets are currently supported.")
        if not hostname:
            raise ScopeValidationError("Target URL must include a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeValidationError("Credentials in target URLs are not allowed.")
        if port is None:
            raise ScopeValidationError(
                "Specify a target port, e.g. http://localhost:3000."
            )
        if not 1 <= port <= 65535:
            raise ScopeValidationError("Target port must be between 1 and 65535.")

        normalized_host = self._normalize_host(hostname)
        if normalized_host not in self.allowed_hosts:
            raise ScopeValidationError(
                f"Unauthorized target host: {normalized_host}. "
                "Add it explicitly to allowed_hosts to authorize it."
            )
        return parsed

    @staticmethod
    def _normalize_host(host):
        normalized = host.strip().rstrip(".").lower()
        if normalized.startswith("[") and normalized.endswith("]"):
            normalized = normalized[1:-1]
        try:
            return ipaddress.ip_address(normalized).compressed
        except ValueError:
            try:
                return normalized.encode("idna").decode("ascii")
            except UnicodeError as error:
                raise ScopeValidationError("Target host is not a valid hostname.") from error

    def validate_and_pin(self):
        """Resolve the authorized hostname and return a URL pinned to a safe IP."""
        host = self._normalize_host(self._parsed.hostname)
        port = self._parsed.port

        try:
            literal_address = ipaddress.ip_address(host)
            addresses = [literal_address]
        except ValueError:
            resolved = self._resolve_with_timeout(host, port)
            addresses = []
            for entry in resolved:
                address = ipaddress.ip_address(entry[4][0].split("%", 1)[0])
                if address not in addresses:
                    addresses.append(address)

        if not addresses:
            raise ScopeValidationError(f"Target host {host} resolved to no addresses.")
        addresses.sort(key=lambda address: address.version)

        local_authorized_host = host in self.DEFAULT_ALLOWED_HOSTS
        for address in addresses:
            if local_authorized_host:
                if address.is_loopback:
                    continue
                raise ScopeValidationError(
                    f"Default local target {host} resolved outside loopback "
                    f"({address})."
                )
            if self.allow_private_addresses:
                continue
            if not address.is_global:
                raise ScopeValidationError(
                    f"Target host {host} resolves to a non-public address "
                    f"({address}); explicitly enable private-address access "
                    "only for an authorized target."
                )

        # Pin the HTTP connection to the exact address validated above. This
        # avoids a second hostname lookup by the HTTP client after validation.
        address = addresses[0]
        pinned_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
        netloc = f"{pinned_host}:{port}"
        return urlunsplit(
            (
                self._parsed.scheme,
                netloc,
                self._parsed.path,
                self._parsed.query,
                "",
            )
        )

    def _resolve_with_timeout(self, host, port):
        """Resolve DNS with a deadline; a timed-out OS resolver cannot be killed."""
        with self._resolution_lock:
            if self._resolution_timed_out:
                raise ScopeValidationError(
                    f"DNS resolution for {host} previously timed out."
                )

            if not _DNS_RESOLUTION_LOCK.acquire(timeout=self.dns_timeout):
                raise ScopeValidationError(
                    "DNS resolution is unavailable because a previous OS "
                    "resolver call has not returned."
                )

            result_queue = queue.Queue(maxsize=1)

            def resolve():
                try:
                    result_queue.put(
                        (True, self._resolver(host, port, type=socket.SOCK_STREAM))
                    )
                except Exception as error:
                    result_queue.put((False, error))
                finally:
                    _DNS_RESOLUTION_LOCK.release()

            resolver_thread = threading.Thread(
                target=resolve,
                name="gramfuzz-dns-resolver",
                daemon=True,
            )
            try:
                resolver_thread.start()
            except BaseException:
                _DNS_RESOLUTION_LOCK.release()
                raise
            try:
                succeeded, result = result_queue.get(timeout=self.dns_timeout)
            except queue.Empty as error:
                self._resolution_timed_out = True
                raise ScopeValidationError(
                    f"DNS resolution for {host} exceeded "
                    f"{self.dns_timeout:g} seconds."
                ) from error

            if not succeeded:
                if isinstance(result, OSError):
                    raise ScopeValidationError(
                        f"Could not resolve target host {host}: {result}"
                    ) from result
                raise ScopeValidationError(
                    f"Could not resolve target host {host}: {result}"
                ) from result
            return result

    @property
    def host_header(self):
        """Return the original host and port for virtual-host routing."""
        hostname = self._normalize_host(self._parsed.hostname)
        if ":" in hostname:
            hostname = f"[{hostname}]"
        return f"{hostname}:{self._parsed.port}"

    @property
    def target_label(self):
        """Return a log-safe origin that omits paths and query parameters."""
        host = self._normalize_host(self._parsed.hostname)
        if ":" in host:
            host = f"[{host}]"
        return f"{self._parsed.scheme}://{host}:{self._parsed.port}"
