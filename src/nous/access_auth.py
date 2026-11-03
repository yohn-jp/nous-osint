"""Verify Cloudflare Access-signed assertions at the private MCP origin.

This module is independent of the Cloudflare OAuth implementation. Access owns
authorization-code/DCR, and the origin validates its *separate* signed JWT.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from starlette.responses import JSONResponse

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_ASSERTION_LENGTH = 16_384
_MAX_JWKS_BYTES = 128_000


class AccessDenied(Exception):
    """Reject an unauthenticated or invalid assertion without exposing details."""


def _json_no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _decode(segment: str) -> bytes:
    if not segment or not _B64URL.fullmatch(segment):
        raise AccessDenied("invalid assertion")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise AccessDenied("invalid assertion") from exc


def _jwt_object(segment: str) -> dict:
    try:
        result = json.loads(_decode(segment), object_pairs_hook=_json_no_duplicates)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise AccessDenied("invalid assertion") from exc
    if not isinstance(result, dict):
        raise AccessDenied("invalid assertion")
    return result


@dataclass(frozen=True)
class AccessIdentity:
    subject: str
    email: str | None


@dataclass(frozen=True)
class AccessConfig:
    issuer: str
    audience: str
    cache_seconds: int = 300

    def __post_init__(self):
        url = urlsplit(self.issuer)
        if (url.scheme != "https" or not url.hostname or
                not url.hostname.endswith(".cloudflareaccess.com") or
                url.username or url.password or url.port or
                url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("Access issuer must be the Cloudflare team HTTPS origin")
        if not self.audience or not self.audience.strip() or len(self.audience) > 256:
            raise ValueError("Access audience is required")
        if not 30 <= self.cache_seconds <= 3600:
            raise ValueError("invalid JWKS cache duration")

    @classmethod
    def from_environment(cls) -> "AccessConfig":
        # Missing configuration must fail at process startup, not grant access.
        return cls(
            issuer=os.environ["CF_ACCESS_ISSUER"].rstrip("/"),
            audience=os.environ["CF_ACCESS_AUDIENCE"],
        )

    @property
    def jwks_url(self) -> str:
        return self.issuer.rstrip("/") + "/cdn-cgi/access/certs"


class AccessVerifier:
    """Thread-safe bounded JWKS cache; fail closed on unknown keys or fetch errors."""

    def __init__(self, config: AccessConfig, *, http_get=None, clock=None):
        self.config = config
        self._get = http_get or httpx.get
        self._clock = clock or time.time
        self._keys = {}
        self._expires_at = 0.0
        self._last_fetch = 0.0
        self._lock = threading.Lock()

    def _refresh(self, *, force: bool = False):
        now = self._clock()
        if not force and self._keys and now < self._expires_at:
            return
        # Unknown key IDs must not trigger an unbounded JWKS download storm.
        if force and self._keys and now - self._last_fetch < 30:
            return
        self._last_fetch = now
        try:
            response = self._get(
                self.config.jwks_url,
                timeout=3.0,
                follow_redirects=False,
            )
            response.raise_for_status()
            if len(response.content) > _MAX_JWKS_BYTES:
                raise ValueError("JWKS response too large")
            raw = response.json()
            if not isinstance(raw, dict) or not isinstance(raw.get("keys"), list):
                raise ValueError("invalid JWKS document")
            keys = {}
            for jwk in raw["keys"]:
                if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
                    continue
                kid = jwk.get("kid")
                if (not isinstance(kid, str) or len(kid) > 256 or
                        not isinstance(jwk.get("n"), str) or
                        not isinstance(jwk.get("e"), str) or
                        jwk.get("alg", "RS256") != "RS256" or
                        jwk.get("use", "sig") != "sig"):
                    continue
                try:
                    key = rsa.RSAPublicNumbers(
                        int.from_bytes(_decode(jwk["e"]), "big"),
                        int.from_bytes(_decode(jwk["n"]), "big"),
                    ).public_key()
                    if key.key_size < 2048:
                        continue
                except (ValueError, TypeError, AccessDenied):
                    continue
                keys[kid] = key
            if not keys:
                raise ValueError("JWKS contains no valid signing keys")
            self._keys = keys
            self._expires_at = now + self.config.cache_seconds
        except (httpx.HTTPError, ValueError, TypeError, AccessDenied) as exc:
            # Expired keys are never accepted after a network failure.
            if now >= self._expires_at:
                self._keys = {}
            raise AccessDenied("Access JWKS unavailable") from exc

    def verify(self, assertion: str | None) -> AccessIdentity:
        if not assertion or len(assertion) > _MAX_ASSERTION_LENGTH:
            raise AccessDenied("missing or oversized Access assertion")
        parts = assertion.split(".")
        if len(parts) != 3:
            raise AccessDenied("invalid assertion")
        header, claims = _jwt_object(parts[0]), _jwt_object(parts[1])
        kid = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
            raise AccessDenied("unsupported assertion header")
        now = self._clock()
        expires = claims.get("exp")
        not_before = claims.get("nbf")
        issued = claims.get("iat")
        audience = claims.get("aud")
        subject = claims.get("sub")
        if (claims.get("iss") != self.config.issuer or
                not (audience == self.config.audience or
                     isinstance(audience, list) and self.config.audience in audience) or
                not isinstance(subject, str) or not subject or
                type(expires) not in (int, float) or expires <= now or
                (not_before is not None and
                 (type(not_before) not in (int, float) or not_before > now + 60)) or
                (issued is not None and
                 (type(issued) not in (int, float) or issued > now + 60))):
            raise AccessDenied("invalid Access claims")
        with self._lock:
            self._refresh()
            if kid not in self._keys:
                self._refresh(force=True)
            key = self._keys.get(kid)
            if key is None or self._clock() >= self._expires_at:
                raise AccessDenied("unknown or expired signing key")
        try:
            signature = _decode(parts[2])
            key.verify(signature, (parts[0] + "." + parts[1]).encode(),
                       padding.PKCS1v15(), hashes.SHA256())
        except (ValueError, InvalidSignature, AccessDenied) as exc:
            raise AccessDenied("invalid Access signature") from exc
        email = claims.get("email")
        return AccessIdentity(subject=subject,
                              email=email.lower() if isinstance(email, str) and email else None)


class AccessAssertionMiddleware:
    """ASGI outer boundary for a dedicated /mcp-only process.

    The upstream Access application protects the public hostname. This
    middleware also rejects locally submitted / forged identity headers.
    """

    def __init__(self, app, verifier: AccessVerifier):
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope.get("path") not in ("/mcp", "/mcp/"):
            return await JSONResponse({"detail": "not found"}, status_code=404)(
                scope, receive, send
            )
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw = headers.get(b"cf-access-jwt-assertion")
        try:
            assertion = raw.decode("ascii") if raw else None
            identity = await asyncio.to_thread(self.verifier.verify, assertion)
        except (UnicodeError, AccessDenied):
            return await JSONResponse({"detail": "forbidden"}, status_code=403)(
                scope, receive, send
            )
        scope.setdefault("state", {})["access_identity"] = identity
        return await self.app(scope, receive, send)
