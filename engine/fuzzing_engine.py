
import logging
import threading
import time
import requests

from engine.scope_validator import ScopeValidator


logger = logging.getLogger(__name__)


class ScanCancelled(RuntimeError):
    """Raised when a scan is cancelled, preserving completed request results."""

    def __init__(self, results):
        super().__init__("Scan cancelled.")
        self.results = list(results)


class _CancellationRequested(RuntimeError):
    """Internal sentinel used to transfer cancellation through request code."""


class FuzzingEngine:
    """
    Sends controlled test inputs to an authorized local web application.

    Local targets are allowed by default; other hosts require an allowlist.
    """

    def __init__(
        self,
        target_url,
        parameter="input",
        method="GET",
        timeout=5,
        delay=0.2,
        max_requests=100,
        allowed_hosts=None,
        allow_private_addresses=False,
        max_response_bytes=1_048_576,
        dns_timeout=3.0,
    ):

        self.target_url = target_url
        self.parameter = parameter
        if not isinstance(method, str):
            raise ValueError("Method must be a string.")
        self.method = method.upper()
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        self.max_response_bytes = max_response_bytes
        self.dns_timeout = dns_timeout

        self.request_count = 0
        self._request_lock = threading.Lock()
        self._cancel_event = threading.Event()
        self._next_request_at = 0.0
        self._scope = ScopeValidator(
            target_url,
            allowed_hosts=allowed_hosts,
            allow_private_addresses=allow_private_addresses,
            dns_timeout=dns_timeout,
        )

        self._validate_configuration()

    def _validate_configuration(self):
        """Validates target and request settings."""

        if self.method not in {"GET", "POST"}:
            raise ValueError(
                "Only GET and POST methods are supported."
            )

        if not isinstance(self.parameter, str) or not self.parameter.strip():
            raise ValueError("Parameter name cannot be empty.")

        if (
            not isinstance(self.timeout, (int, float))
            or isinstance(self.timeout, bool)
            or not 1 <= self.timeout <= 15
        ):
            raise ValueError("Timeout must be between 1 and 15 seconds.")

        if (
            not isinstance(self.delay, (int, float))
            or isinstance(self.delay, bool)
            or self.delay < 0.2
        ):
            raise ValueError("Delay must be at least 0.2 seconds.")

        if (
            not isinstance(self.max_requests, int)
            or isinstance(self.max_requests, bool)
            or not 1 <= self.max_requests <= 100
        ):
            raise ValueError(
                "Maximum requests must be between 1 and 100."
            )

        if (
            not isinstance(self.max_response_bytes, int)
            or isinstance(self.max_response_bytes, bool)
            or not 1 <= self.max_response_bytes <= 10_485_760
        ):
            raise ValueError(
                "Maximum response bytes must be between 1 and 10485760."
            )

        logger.info(
            "Initialized authorized scan target=%s scope_hosts=%s "
            "method=%s max_requests=%d",
            self._scope.target_label,
            sorted(self._scope.allowed_hosts),
            self.method,
            self.max_requests,
        )

    def cancel(self):
        """Request cancellation; an in-flight HTTP request ends at its timeout."""
        self._cancel_event.set()

    @property
    def target_label(self):
        """Return the validated, query-free target origin."""
        return self._scope.target_label

    def _reserve_request(self):
        """Enforce cancellation, request count, and a shared minimum delay."""
        with self._request_lock:
            if self._cancel_event.is_set():
                raise _CancellationRequested("Scan cancelled.")
            if self.request_count >= self.max_requests:
                raise RuntimeError("Maximum request limit reached.")

            wait = self._next_request_at - time.monotonic()
            if wait > 0 and self._cancel_event.wait(wait):
                raise _CancellationRequested("Scan cancelled.")
            if self._cancel_event.is_set():
                raise _CancellationRequested("Scan cancelled.")

            self.request_count += 1
            self._next_request_at = time.monotonic() + self.delay

    def _read_limited_response(self, response, deadline):
        """Read at most max_response_bytes plus one byte to detect truncation."""
        body = bytearray()
        truncated = False
        for chunk in response.iter_content(chunk_size=8192):
            if time.monotonic() > deadline:
                raise requests.Timeout("Total HTTP response deadline exceeded.")
            if not chunk:
                continue
            remaining = self.max_response_bytes + 1 - len(body)
            body.extend(chunk[:remaining])
            if len(body) > self.max_response_bytes:
                break

        if len(body) > self.max_response_bytes:
            truncated = True
            del body[self.max_response_bytes :]
        encoding = getattr(response, "encoding", None) or "utf-8"
        return bytes(body), bytes(body).decode(encoding, errors="replace"), truncated

    def send_payload(self, payload, metadata=None):
        """Sends one test input and records response metadata."""

        if not isinstance(payload, str):
            raise TypeError("Payload must be a string.")

        if not payload:
            raise ValueError("Payload cannot be empty.")

        if metadata is not None:
            metadata = self._safe_payload_metadata(metadata)
        pinned_url = self._scope.validate_and_pin()
        self._reserve_request()
        request_started = time.monotonic()

        request_data = {
            self.parameter: payload
        }

        session = requests.Session()
        session.trust_env = False
        try:
            response = session.request(
                method=self.method,
                url=pinned_url,
                params=request_data if self.method == "GET" else None,
                data=request_data if self.method == "POST" else None,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
                headers={"Host": self._scope.host_header},
                proxies={},
            )
            try:
                content, response_text, truncated = self._read_limited_response(
                    response, request_started + self.timeout
                )
                result = {
                    "payload": payload,
                    "method": self.method,
                    "target": self._scope.target_label,
                    "parameter": self.parameter,
                    "status_code": response.status_code,
                    "response_time": time.monotonic() - request_started,
                    "response_length": len(content),
                    "response_text": response_text[:2000],
                    "response_truncated": truncated,
                    "error": None,
                }
                if metadata is not None:
                    result.update(self._safe_payload_metadata(metadata))
                return result
            finally:
                response.close()
        except requests.RequestException as error:
            logger.warning(
                "HTTP request failed target=%s error=%s",
                self._scope.target_label,
                type(error).__name__,
            )
            result = {
                "payload": payload,
                "method": self.method,
                "target": self._scope.target_label,
                "parameter": self.parameter,
                "status_code": None,
                "response_time": time.monotonic() - request_started,
                "response_length": None,
                "response_text": None,
                "response_truncated": False,
                "error": type(error).__name__,
            }
            if metadata is not None:
                result.update(self._safe_payload_metadata(metadata))
            return result
        finally:
            session.close()

    @staticmethod
    def _safe_payload_metadata(metadata):
        if not isinstance(metadata, dict):
            raise TypeError("Payload metadata must be a dictionary.")
        permitted = {"payload_id", "strategy", "original_payload", "attempt"}
        safe_metadata = {
            key: value for key, value in metadata.items() if key in permitted
        }
        for key in ("payload_id", "strategy", "original_payload"):
            if key in safe_metadata and not isinstance(safe_metadata[key], str):
                raise TypeError(f"Payload metadata '{key}' must be a string.")
        if "attempt" in safe_metadata and (
            not isinstance(safe_metadata["attempt"], int)
            or isinstance(safe_metadata["attempt"], bool)
            or safe_metadata["attempt"] < 1
        ):
            raise TypeError("Payload metadata 'attempt' must be a positive integer.")
        return safe_metadata

    def run(self, payloads):
        """Sends a collection of test inputs."""

        results = []

        for payload in payloads:
            if self._cancel_event.is_set():
                raise ScanCancelled(results)
            if isinstance(payload, dict):
                if "payload" not in payload:
                    raise ValueError("Payload entries must include 'payload'.")
                metadata = {
                    key: value
                    for key, value in payload.items()
                    if key != "payload"
                }
                request_payload = payload["payload"]
            else:
                metadata = None
                request_payload = payload
            try:
                result = self.send_payload(request_payload, metadata=metadata)
            except _CancellationRequested as error:
                raise ScanCancelled(results) from error
            results.append(result)
        return results
