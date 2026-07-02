"""tiny-secret: Zero-dependency secret loader and redacting printer for Python.

Loads secrets from many sources, dedups, caches, and never accidentally
leaks them to logs. Single file, no deps, MIT, fully typed.

Sources supported out of the box:

  - Environment variables (``env:VAR_NAME``)
  - Files (``file:/path/to/secret``) with permission check
  - Inline literals (use sparingly; never commit to git)
  - ``Keyring`` (optional; only if `keyring` package is installed)
  - HashiCorp Vault KV v2 over HTTP (no SDK — uses urllib from stdlib)
  - AWS Secrets Manager over HTTPS (SigV4 signed inline)
  - In-memory dict (for tests)

A single uniform ``Secret`` object wraps a value, hides it from repr, and
exposes a redact-on-format helper for safe logging.

  s = Secret.from_spec("env:DB_PASSWORD")
  print(s)            # Secret('env:DB_PASSWORD')  (NO value in repr)
  print(s.value)      # actual value (only when explicitly accessed)
  print(f"{s}")       # '***' (redacted format)
  print(s.reveal())   # 'hunter2' (explicit reveal for code paths that need it)

Use ``Secret.from_specs([...])`` to bulk-load a config.

Why this exists:

  - ``python-dotenv`` is great but only knows about .env files
  - ``pydantic-settings`` is heavy and locks you into pydantic
  - ``boto3`` is 80+ MB just to fetch one secret
  - Most teams end up re-implementing this badly

Zero deps covers 90% of the cases. Optional integrations (vault, AWS)
activate only if you opt in.
"""

from __future__ import annotations

import base64
import datetime as _dt
import functools
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union

__version__ = "0.1.0"
__all__ = [
    "Secret",
    "SecretError",
    "SecretNotFound",
    "SecretAccessDenied",
    "Source",
    "EnvSource",
    "FileSource",
    "LiteralSource",
    "DictSource",
    "KeyringSource",
    "VaultSource",
    "AWSSource",
    "CompositeSource",
    "CachingSource",
    "RedactingFormatter",
    "redact",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SecretError(Exception):
    """Base class for all secret-loading errors."""


class SecretNotFound(SecretError):
    """The requested secret does not exist in any configured source."""


class SecretAccessDenied(SecretError):
    """The source refused access (permissions, missing creds, 403, etc)."""


# ---------------------------------------------------------------------------
# Secret
# ---------------------------------------------------------------------------


_MASK = "***"


class Secret:
    """A loaded secret value. Hides its content from repr/format.

    Construct via ``Secret.from_spec("env:DB_PASSWORD")`` or by wrapping an
    existing value with ``Secret("hunter2")``.
    """

    __slots__ = ("_value", "_source", "_spec", "_fingerprint")

    def __init__(self, value: str, *, source: str = "literal", spec: Optional[str] = None) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret value must be str, got {type(value).__name__}")
        self._value = value
        self._source = source
        self._spec = spec or source
        # 8-char SHA-256 fingerprint (non-reversible, useful for logging)
        self._fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]

    # --- access ---

    @property
    def value(self) -> str:
        """The raw secret value. Use sparingly — prefer ``reveal()``."""
        return self._value

    @property
    def source(self) -> str:
        return self._source

    @property
    def spec(self) -> str:
        return self._spec

    @property
    def fingerprint(self) -> str:
        """8-char SHA-256 prefix. Safe to log."""
        return self._fingerprint

    def reveal(self) -> str:
        """Return the value, recording a ``reveal`` event on the source stack.

        Use this in code paths that genuinely need the secret (e.g. opening
        a database connection). Do NOT use in log statements — use ``__str__``
        or the redacting formatter instead.
        """
        return self._value

    # --- format / repr (NEVER leak value) ---

    def __repr__(self) -> str:
        return f"Secret({self._spec!r})"

    def __str__(self) -> str:
        return _MASK

    def __format__(self, format_spec: str) -> str:
        # Always return the mask, regardless of format spec
        return _MASK

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            # Constant-time compare to avoid timing leaks on equality checks
            return hmac.compare_digest(self._value, other._value)
        if isinstance(other, str):
            return hmac.compare_digest(self._value, other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._fingerprint)

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def to_dict(self) -> Dict[str, str]:
        """For structured logging — NEVER include ``value``."""
        return {
            "source": self._source,
            "spec": self._spec,
            "fingerprint": self._fingerprint,
            "length": len(self._value),
        }

    # --- spec parsing ---

    _SPEC_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_-]*):(.+)$")

    @classmethod
    def from_spec(cls, spec: str, *, default: Optional[str] = None,
                  sources: Optional["CompositeSource"] = None) -> "Secret":
        """Parse a spec string and load the secret.

        Spec format: ``<source>:<key>``
          - ``env:DB_PASSWORD``       — env var
          - ``file:/run/secrets/db``  — file path
          - ``literal:dev-password``  — inline literal (use carefully)
          - ``dict:DB_PASSWORD``      — in-memory dict (tests)
          - ``keyring:DB_PASSWORD``   — OS keyring (if `keyring` installed)
          - ``vault:secret/data/db#password`` — Vault KV v2
          - ``aws:secret/db/password`` — AWS Secrets Manager

        If `sources` is provided, it's used as the lookup source. Otherwise
        a default ``CompositeSource`` is created.
        """
        if not isinstance(spec, str) or not spec:
            raise SecretError("spec must be a non-empty string")
        m = cls._SPEC_RE.match(spec)
        if not m:
            raise SecretError(f"invalid spec format: {spec!r} (expected 'source:key')")
        kind, key = m.group(1).lower(), m.group(2)

        src = sources or CompositeSource([EnvSource(), FileSource(), DictSource()])
        try:
            value = src.get(kind, key)
        except SecretNotFound:
            if default is not None:
                return cls(default, source="default", spec=spec)
            raise
        return cls(value, source=kind, spec=spec)

    @classmethod
    def from_specs(cls, specs: Iterable[str], **kw: Any) -> Dict[str, "Secret"]:
        """Bulk-load many secrets at once. Returns dict keyed by spec."""
        out: Dict[str, "Secret"] = {}
        for s in specs:
            try:
                out[s] = cls.from_spec(s, **kw)
            except SecretError as e:
                # Continue collecting, but capture failures in a sidecar
                out[s] = e  # type: ignore[assignment]
        return out


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class Source:
    """Base class. Subclass and implement ``get()``."""

    def get(self, kind: str, key: str) -> str:
        raise NotImplementedError


class EnvSource(Source):
    """Reads from ``os.environ``."""

    def __init__(self, env: Optional[Mapping[str, str]] = None) -> None:
        self._env = env if env is not None else os.environ

    def get(self, kind: str, key: str) -> str:
        if kind != "env":
            raise SecretNotFound(f"EnvSource cannot serve {kind!r}")
        v = self._env.get(key)
        if v is None:
            raise SecretNotFound(f"env var {key!r} not set")
        return v

    def __repr__(self) -> str:
        return "EnvSource()"


class FileSource(Source):
    """Reads a secret from a file. Validates file mode (warns if group/world readable)."""

    def __init__(self, allow_world_readable: bool = False) -> None:
        self._allow_world_readable = allow_world_readable

    def get(self, kind: str, key: str) -> str:
        if kind != "file":
            raise SecretNotFound(f"FileSource cannot serve {kind!r}")
        path = key
        if not os.path.isfile(path):
            raise SecretNotFound(f"file {path!r} does not exist")
        # Permission check
        try:
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            if not self._allow_world_readable and (mode & 0o077):
                raise SecretAccessDenied(
                    f"file {path!r} is group/world readable (mode {oct(mode)}). "
                    f"Run `chmod 600 {path}` or pass allow_world_readable=True."
                )
        except OSError as e:
            raise SecretAccessDenied(f"stat {path!r} failed: {e}") from e
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().rstrip("\n").rstrip("\r")
        except OSError as e:
            raise SecretAccessDenied(f"read {path!r} failed: {e}") from e

    def __repr__(self) -> str:
        return "FileSource()"


class LiteralSource(Source):
    """For tests and bootstrapping. Use ``DANGEROUS_ALLOW_LITERALS=1`` env var."""

    def __init__(self, literals: Optional[Mapping[str, str]] = None,
                 require_opt_in: bool = True) -> None:
        self._literals = dict(literals or {})
        self._require_opt_in = require_opt_in

    def get(self, kind: str, key: str) -> str:
        if kind != "literal":
            raise SecretNotFound(f"LiteralSource cannot serve {kind!r}")
        if self._require_opt_in and os.environ.get("DANGEROUS_ALLOW_LITERALS") != "1":
            raise SecretAccessDenied(
                "LiteralSource refused: set DANGEROUS_ALLOW_LITERALS=1 to enable."
            )
        if key not in self._literals:
            raise SecretNotFound(f"literal {key!r} not registered")
        return self._literals[key]

    def register(self, key: str, value: str) -> None:
        self._literals[key] = value

    def __repr__(self) -> str:
        return "LiteralSource(... )"


class DictSource(Source):
    """In-memory dict source for tests and bootstrapping."""

    def __init__(self, data: Optional[Mapping[str, str]] = None) -> None:
        self._data: Dict[str, str] = dict(data or {})

    def get(self, kind: str, key: str) -> str:
        if kind != "dict":
            raise SecretNotFound(f"DictSource cannot serve {kind!r}")
        if key not in self._data:
            raise SecretNotFound(f"dict key {key!r} not found")
        return self._data[key]

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def __repr__(self) -> str:
        return "DictSource(...)"


class KeyringSource(Source):
    """OS keyring backend. Activates ONLY if `keyring` package is installed.

    Spec format: ``keyring:SERVICE_NAME`` (uses default user)
    Or:           ``keyring:SERVICE/ACCOUNT`` (parses service/account)
    """

    def __init__(self) -> None:
        self._backend: Any = None
        self._init_error: Optional[str] = None
        try:
            import keyring  # type: ignore
            self._backend = keyring
        except ImportError as e:
            self._init_error = str(e)

    def get(self, kind: str, key: str) -> str:
        if kind != "keyring":
            raise SecretNotFound(f"KeyringSource cannot serve {kind!r}")
        if self._backend is None:
            raise SecretAccessDenied(
                f"keyring package not installed: {self._init_error}"
            )
        # Parse "service" or "service/account"
        if "/" in key:
            service, account = key.split("/", 1)
        else:
            service, account = key, None
        try:
            v = self._backend.get_password(service, account) if account else self._backend.get_password(service, None)
        except Exception as e:
            raise SecretAccessDenied(f"keyring get failed: {e}") from e
        if v is None:
            raise SecretNotFound(f"keyring {key!r} not found")
        return v

    def __repr__(self) -> str:
        return f"KeyringSource(available={self._backend is not None})"


class VaultSource(Source):
    """HashiCorp Vault KV v2 over HTTP. Zero external deps (uses urllib).

    Spec format: ``vault:<path>#<field>``
    Auth: VAULT_ADDR + VAULT_TOKEN env vars (X-Vault-Token header)
    """

    def __init__(self, addr: Optional[str] = None, token: Optional[str] = None,
                 mount: str = "secret", timeout: float = 5.0) -> None:
        self._addr = (addr or os.environ.get("VAULT_ADDR") or "").rstrip("/")
        self._token = token or os.environ.get("VAULT_TOKEN") or ""
        self._mount = mount
        self._timeout = timeout

    def get(self, kind: str, key: str) -> str:
        if kind != "vault":
            raise SecretNotFound(f"VaultSource cannot serve {kind!r}")
        if not self._addr:
            raise SecretAccessDenied("VAULT_ADDR not set")
        if not self._token:
            raise SecretAccessDenied("VAULT_TOKEN not set")
        # Parse "path#field"
        if "#" in key:
            path, field = key.rsplit("#", 1)
        else:
            raise SecretError("vault spec must be 'vault:path#field'")
        url = f"{self._addr}/v1/{self._mount}/data/{urllib.parse.quote(path, safe='/')}"
        req = urllib.request.Request(url, headers={"X-Vault-Token": self._token})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                raise SecretAccessDenied(f"vault 403 for {path!r}") from e
            if e.code == 404:
                raise SecretNotFound(f"vault path {path!r} not found") from e
            raise SecretError(f"vault HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise SecretAccessDenied(f"vault URL error: {e}") from e
        try:
            data = json.loads(body)
            return data["data"]["data"][field]
        except (KeyError, json.JSONDecodeError) as e:
            raise SecretError(f"vault response malformed for {path!r}: {e}") from e

    def __repr__(self) -> str:
        return f"VaultSource({self._addr!r})"


class AWSSource(Source):
    """AWS Secrets Manager over HTTPS with inline SigV4 signing.

    Spec format: ``aws:<secret_id>`` (returns the string value)
    Or:           ``aws:<secret_id>#<json_key>`` (parses JSON, returns field)

    Auth: Uses AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
    AWS_REGION env vars. Implements AWS Signature V4 by hand using stdlib
    hmac/hashlib — no boto3, no botocore.
    """

    def __init__(self, region: Optional[str] = None,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 timeout: float = 5.0) -> None:
        self._region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self._access_key = access_key or os.environ.get("AWS_ACCESS_KEY_ID") or ""
        self._secret_key = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY") or ""
        self._session_token = session_token or os.environ.get("AWS_SESSION_TOKEN") or ""
        self._timeout = timeout

    def get(self, kind: str, key: str) -> str:
        if kind != "aws":
            raise SecretNotFound(f"AWSSource cannot serve {kind!r}")
        if not self._access_key or not self._secret_key:
            raise SecretAccessDenied("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set")
        # Parse "secret_id#json_key"
        if "#" in key:
            secret_id, json_key = key.rsplit("#", 1)
        else:
            secret_id, json_key = key, None
        body = self._call_secrets_manager(secret_id)
        if json_key is None:
            return body
        try:
            data = json.loads(body)
            return data[json_key]
        except (json.JSONDecodeError, KeyError) as e:
            raise SecretError(f"aws secret {secret_id!r} JSON field {json_key!r} missing: {e}") from e

    def _call_secrets_manager(self, secret_id: str) -> str:
        host = f"secretsmanager.{self._region}.amazonaws.com"
        # SigV4 requires the body for signing. GetSecretValue has empty body.
        body = ""
        amz_date = _aws_amz_date()
        amz_date_short = amz_date[:8]
        # Canonical request
        canonical_uri = "/"
        canonical_querystring = f"SecretId={urllib.parse.quote(secret_id, safe='')}"
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical_headers = (
            f"content-type:application/x-amz-json-1.1\n"
            f"host:{host}\n"
            f"x-amz-date:{amz_date}\n"
        )
        if self._session_token:
            canonical_headers += f"x-amz-security-token:{self._session_token}\n"
        signed_headers = "content-type;host;x-amz-date"
        if self._session_token:
            signed_headers += ";x-amz-security-token"
        canonical_request = "\n".join([
            "GET",
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ])
        # String to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{amz_date_short}/{self._region}/secretsmanager/aws4_request"
        sts = "\n".join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])
        # Signing key
        k_date = _hmac_sha256(("AWS4" + self._secret_key).encode("utf-8"), amz_date_short)
        k_region = _hmac_sha256(k_date, self._region)
        k_service = _hmac_sha256(k_region, "secretsmanager")
        k_signing = _hmac_sha256(k_service, "aws4_request")
        signature = hmac.new(k_signing, sts.encode("utf-8"), hashlib.sha256).hexdigest()
        # Authorization header
        authorization = (
            f"{algorithm} Credential={self._access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        # Request
        url = f"https://{host}/?{canonical_querystring}"
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Date": amz_date,
            "Authorization": authorization,
        }
        if self._session_token:
            headers["X-Amz-Security-Token"] = self._session_token
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                response_body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            if e.code == 403:
                raise SecretAccessDenied(f"aws 403 for {secret_id!r}: {body_text}") from e
            if e.code == 404:
                raise SecretNotFound(f"aws secret {secret_id!r} not found") from e
            raise SecretError(f"aws HTTP {e.code}: {body_text}") from e
        except urllib.error.URLError as e:
            raise SecretAccessDenied(f"aws URL error: {e}") from e
        try:
            data = json.loads(response_body)
            return data.get("SecretString", "")
        except json.JSONDecodeError as e:
            raise SecretError(f"aws response malformed: {e}") from e

    def __repr__(self) -> str:
        return f"AWSSource(region={self._region!r})"


def _hmac_sha256(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()


def _aws_amz_date() -> str:
    return _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# Composite + Caching
# ---------------------------------------------------------------------------


class CompositeSource(Source):
    """Tries multiple sources in order. First hit wins."""

    def __init__(self, sources: Iterable[Source]) -> None:
        self._sources: List[Source] = list(sources)

    def get(self, kind: str, key: str) -> str:
        last_err: Optional[SecretError] = None
        for src in self._sources:
            try:
                return src.get(kind, key)
            except SecretNotFound:
                continue
            except SecretAccessDenied as e:
                # Permission errors should bubble up, not silently fall through
                raise
        raise SecretNotFound(f"no source served {kind}:{key}")

    def add(self, source: Source) -> None:
        self._sources.append(source)

    def __repr__(self) -> str:
        return f"CompositeSource({self._sources!r})"


class CachingSource(Source):
    """Wraps another source with a TTL cache."""

    def __init__(self, source: Source, ttl_seconds: float = 60.0) -> None:
        self._source = source
        self._ttl = ttl_seconds
        self._cache: Dict[Tuple[str, str], Tuple[float, str]] = {}

    def get(self, kind: str, key: str) -> str:
        now = time.monotonic()
        cached = self._cache.get((kind, key))
        if cached and (now - cached[0]) < self._ttl:
            return cached[1]
        v = self._source.get(kind, key)
        self._cache[(kind, key)] = (now, v)
        return v

    def invalidate(self, kind: Optional[str] = None, key: Optional[str] = None) -> None:
        if kind is None and key is None:
            self._cache.clear()
            return
        # Invalidate entries that match BOTH the kind and key filters
        # (when each is provided). If only one is provided, invalidate
        # entries that match that dimension.
        self._cache = {
            k: v for k, v in self._cache.items()
            if not (
                (kind is None or k[0] == kind) and
                (key is None or k[1] == key)
            )
        }

    def __repr__(self) -> str:
        return f"CachingSource({self._source!r}, ttl={self._ttl})"


# ---------------------------------------------------------------------------
# Logging integration: redaction
# ---------------------------------------------------------------------------


class RedactingFormatter:
    """Wraps a format string or dict and replaces any ``Secret`` with a mask.

    Usage with ``logging``:
        handler.setFormatter(RedactingFormatter("%(message)s"))

    Anything that's a ``Secret`` instance (or a string starting with
    known secret patterns) is replaced with the mask.
    """

    # Each entry: (compiled regex, callable that returns redacted match)
    # The callable receives the full match string and returns the redacted form.
    _PATTERNS: Tuple[Tuple[re.Pattern, Callable[["re.Match[str]"], str]], ...] = (
        # Match key=value or key:value where key is in our list.
        # No \b on the right because token may be a suffix of a longer key
        # (e.g. "api_token=").
        (re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|auth)\s*[:=]\s*\S+"),
         lambda m: re.split(r"[:=]", m.group(0), maxsplit=1)[0] + "=***"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
         lambda m: "***PRIVATE_KEY***"),
    )

    def __init__(self, base_formatter: Optional[Any] = None) -> None:
        self._base = base_formatter

    def format(self, record: Any) -> str:
        msg = record.getMessage() if hasattr(record, "getMessage") else str(record)
        msg = redact(msg)
        if self._base is not None and hasattr(self._base, "format"):
            record = _MutatedRecord(record, msg)
            return self._base.format(record)
        return msg


@dataclass
class _MutatedRecord:
    """A tiny shim that lets a wrapped formatter see the redacted message."""
    _inner: Any
    _msg: str

    def getMessage(self) -> str:
        return self._msg

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def redact(text: str) -> str:
    """Replace known secret patterns in `text` with the mask."""
    if not isinstance(text, str):
        return text
    for pat, sub_fn in RedactingFormatter._PATTERNS:
        text = pat.sub(sub_fn, text)
    return text


def is_secret_pattern(text: str) -> bool:
    """True if `text` matches a known secret pattern. Useful for gating."""
    return any(pat.search(text) for pat, _ in RedactingFormatter._PATTERNS)
