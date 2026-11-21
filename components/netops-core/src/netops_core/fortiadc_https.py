"""Pinned FortiADC management HTTPS with an in-memory login session."""

from contextlib import contextmanager
import hashlib
import hmac
import http.client
import json
import re
import ssl
from urllib.parse import urlencode


class RequestError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class Management:
    def __init__(self, address, port, pin):
        if not isinstance(pin, str) or re.fullmatch(r"[a-f0-9]{64}", pin) is None:
            raise RequestError("https_pin_required")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.connection = http.client.HTTPSConnection(address, port, timeout=10, context=context)
        self.pin = pin
        self.token = None
        self.cookies = {}

    def _request(self, method, path, body=None, content_type=None):
        headers = {"Accept": "application/json"}
        if self.token is not None:
            headers["Authorization"] = "Bearer " + self.token
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.cookies.items())
        if content_type:
            headers["Content-Type"] = content_type
        try:
            if self.connection.sock is None:
                self.connection.connect()
            fingerprint = hashlib.sha256(self.connection.sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(fingerprint, self.pin):
                raise RequestError("tls_pin_mismatch")
            self.connection.request(method, path, body, headers)
            with self.connection.getresponse() as response:
                if response.status != 200:
                    raise RequestError({401: "authentication_failed", 403: "permission_denied"}.get(
                        response.status, "http_status"))
                for key, value in response.getheaders():
                    if key.lower() == "set-cookie":
                        name, sep, item = value.split(";", 1)[0].partition("=")
                        if sep and name in {"last_access_time", "authid"} and re.fullmatch(r"[A-Za-z0-9_.-]+", item):
                            self.cookies[name] = item
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000 or response.length not in (0, None):
                    raise RequestError("incomplete_output")
            answer = json.loads(raw)
            if not isinstance(answer, dict):
                raise RequestError("incomplete_output")
            return answer
        except TimeoutError:
            self.connection.close()
            raise RequestError("timeout") from None
        except (OSError, http.client.HTTPException):
            self.connection.close()
            raise RequestError("transport_error") from None
        except (ValueError, RecursionError) as exc:
            self.connection.close()
            if isinstance(exc, RequestError):
                raise
            raise RequestError("incomplete_output") from None

    @contextmanager
    def login(self, username, password):
        try:
            answer = self._request("POST", "/api/user/login", json.dumps(
                {"username": username, "password": password}).encode(), "application/json")
            token = answer.get("token")
            if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9._~-]{8,8192}", token) is None:
                raise RequestError("authentication_failed")
            self.token = token
            yield self
        finally:
            try:
                if self.token is not None:
                    self._request("GET", "/api/user/logout")
            except RequestError:
                pass
            finally:
                self.connection.close()
                self.token = None
                self.cookies.clear()

    def read(self, endpoint, **parameters):
        suffix = "?" + urlencode(parameters) if parameters else ""
        response = self._request("GET", "/api/" + endpoint + suffix)
        if "payload" not in response:
            raise RequestError("incomplete_output")
        return response["payload"]

    def upload_certificate(self, content_type, body):
        return self._request("POST", "/api/upload/certificate_local", body, content_type).get("payload")
