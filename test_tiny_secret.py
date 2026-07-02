"""Tests for tiny-secret — run with `python test_tiny_secret.py`. Stdlib only."""

import json
import logging
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import tiny_secret as ts


# ---------------------------------------------------------------------------
# Secret value object
# ---------------------------------------------------------------------------


class TestSecret(unittest.TestCase):
    def test_basic_repr_hides_value(self):
        s = ts.Secret("hunter2")
        # Repr should NOT include the raw value
        self.assertNotIn("hunter2", repr(s))
        # It should show 'Secret(...)' only
        self.assertIn("Secret", repr(s))

    def test_str_is_masked(self):
        s = ts.Secret("hunter2")
        self.assertEqual(str(s), "***")

    def test_format_is_masked(self):
        s = ts.Secret("hunter2")
        self.assertEqual(f"value={s}", "value=***")
        self.assertEqual(f"{s:>20}", "***")

    def test_reveal_returns_value(self):
        s = ts.Secret("hunter2")
        self.assertEqual(s.reveal(), "hunter2")
        self.assertEqual(s.value, "hunter2")

    def test_fingerprint_is_short(self):
        s = ts.Secret("hunter2")
        self.assertEqual(len(s.fingerprint), 8)
        # Different values → different fingerprints
        s2 = ts.Secret("different")
        self.assertNotEqual(s.fingerprint, s2.fingerprint)

    def test_equality_value(self):
        a = ts.Secret("hunter2")
        b = ts.Secret("hunter2")
        c = ts.Secret("other")
        self.assertTrue(a == b)
        self.assertFalse(a == c)
        # Compare with str
        self.assertTrue(a == "hunter2")
        self.assertFalse(a == "other")

    def test_equality_with_secret_constant_time(self):
        # The implementation should use hmac.compare_digest (tested by code
        # review; behaviorally just need to verify == works)
        a = ts.Secret("hunter2")
        self.assertTrue(a == "hunter2")

    def test_to_dict_no_value(self):
        s = ts.Secret("hunter2", source="env", spec="env:DB")
        d = s.to_dict()
        self.assertEqual(d["source"], "env")
        self.assertEqual(d["spec"], "env:DB")
        self.assertEqual(d["length"], 7)
        self.assertNotIn("value", d)

    def test_hashable(self):
        s = ts.Secret("hunter2")
        s2 = ts.Secret("hunter2")
        # Same value → same hash
        self.assertEqual(hash(s), hash(s2))
        # Usable in a set
        self.assertEqual(len({s, s2}), 1)

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            ts.Secret(12345)  # type: ignore[arg-type]

    def test_length_and_bool(self):
        s = ts.Secret("x")
        self.assertEqual(len(s), 1)
        self.assertTrue(bool(s))
        empty = ts.Secret("")
        self.assertEqual(len(empty), 0)
        self.assertFalse(bool(empty))


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


class TestSpecParsing(unittest.TestCase):
    def test_invalid_format(self):
        with self.assertRaises(ts.SecretError):
            ts.Secret.from_spec("noseparator")
        with self.assertRaises(ts.SecretError):
            ts.Secret.from_spec("")

    def test_valid_formats(self):
        # Just parse the spec — load from default env (likely not present)
        try:
            s = ts.Secret.from_spec("env:NONEXISTENT_TEST_VAR_XYZ", default="fallback")
            self.assertEqual(s.value, "fallback")
        except ts.SecretNotFound:
            pass  # also acceptable

    def test_default_fallback(self):
        s = ts.Secret.from_spec("env:DEFINITELY_NOT_SET_XYZ_123",
                                default="the-default")
        self.assertEqual(s.value, "the-default")
        self.assertEqual(s.source, "default")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class TestEnvSource(unittest.TestCase):
    def test_get_existing(self):
        os.environ["TINY_SECRET_TEST"] = "hello"
        src = ts.EnvSource()
        self.assertEqual(src.get("env", "TINY_SECRET_TEST"), "hello")

    def test_get_missing(self):
        src = ts.EnvSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("env", "TINY_SECRET_DEFINITELY_NOT_SET_QQQQ")

    def test_wrong_kind(self):
        src = ts.EnvSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("file", "x")

    def test_custom_env(self):
        src = ts.EnvSource(env={"FOO": "bar"})
        self.assertEqual(src.get("env", "FOO"), "bar")


class TestFileSource(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_get_existing(self):
        path = os.path.join(self.tmp, "secret")
        with open(path, "w") as f:
            f.write("the-value\n")
        os.chmod(path, 0o600)
        src = ts.FileSource()
        self.assertEqual(src.get("file", path), "the-value")

    def test_get_missing(self):
        src = ts.FileSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("file", "/no/such/path")

    def test_world_readable_rejected(self):
        path = os.path.join(self.tmp, "secret")
        with open(path, "w") as f:
            f.write("the-value")
        os.chmod(path, 0o644)  # world-readable
        src = ts.FileSource()
        with self.assertRaises(ts.SecretAccessDenied):
            src.get("file", path)

    def test_world_readable_allowed(self):
        path = os.path.join(self.tmp, "secret")
        with open(path, "w") as f:
            f.write("the-value")
        os.chmod(path, 0o644)
        src = ts.FileSource(allow_world_readable=True)
        self.assertEqual(src.get("file", path), "the-value")

    def test_wrong_kind(self):
        src = ts.FileSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("env", "x")

    def test_trailing_newline_stripped(self):
        path = os.path.join(self.tmp, "secret")
        with open(path, "w") as f:
            f.write("value\n\n")
        os.chmod(path, 0o600)
        src = ts.FileSource()
        self.assertEqual(src.get("file", path), "value")


class TestLiteralSource(unittest.TestCase):
    def test_refused_without_opt_in(self):
        src = ts.LiteralSource({"db": "value"})
        with self.assertRaises(ts.SecretAccessDenied):
            src.get("literal", "db")

    def test_allowed_with_opt_in(self):
        os.environ["DANGEROUS_ALLOW_LITERALS"] = "1"
        try:
            src = ts.LiteralSource({"db": "value"})
            self.assertEqual(src.get("literal", "db"), "value")
        finally:
            del os.environ["DANGEROUS_ALLOW_LITERALS"]

    def test_missing_key(self):
        os.environ["DANGEROUS_ALLOW_LITERALS"] = "1"
        try:
            src = ts.LiteralSource()
            with self.assertRaises(ts.SecretNotFound):
                src.get("literal", "nope")
        finally:
            del os.environ["DANGEROUS_ALLOW_LITERALS"]


class TestDictSource(unittest.TestCase):
    def test_get(self):
        src = ts.DictSource({"a": "1", "b": "2"})
        self.assertEqual(src.get("dict", "a"), "1")
        self.assertEqual(src.get("dict", "b"), "2")

    def test_missing(self):
        src = ts.DictSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("dict", "nope")

    def test_wrong_kind(self):
        src = ts.DictSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("env", "a")

    def test_set(self):
        src = ts.DictSource()
        src.set("a", "1")
        self.assertEqual(src.get("dict", "a"), "1")


class TestKeyringSource(unittest.TestCase):
    def test_unavailable(self):
        # keyring probably isn't installed in CI
        src = ts.KeyringSource()
        with self.assertRaises(ts.SecretNotFound):
            src.get("not-keyring", "x")  # wrong kind
        # If keyring isn't installed, get("keyring", ...) raises AccessDenied
        if src._backend is None:
            with self.assertRaises(ts.SecretAccessDenied):
                src.get("keyring", "x")


class TestCompositeSource(unittest.TestCase):
    def test_first_hit_wins(self):
        c = ts.CompositeSource([
            ts.DictSource({"a": "first"}),
            ts.DictSource({"a": "second"}),
        ])
        self.assertEqual(c.get("dict", "a"), "first")

    def test_falls_through(self):
        c = ts.CompositeSource([
            ts.DictSource({}),  # no a
            ts.DictSource({"a": "fallback"}),
        ])
        self.assertEqual(c.get("dict", "a"), "fallback")

    def test_all_miss_raises(self):
        c = ts.CompositeSource([
            ts.DictSource({}),
            ts.DictSource({}),
        ])
        with self.assertRaises(ts.SecretNotFound):
            c.get("dict", "x")

    def test_access_denied_bubbles(self):
        # EnvSource doesn't serve 'file' kind — should bubble, not silently fall through
        c = ts.CompositeSource([
            ts.EnvSource(),
            ts.DictSource({"x": "value"}),
        ])
        # Asking for 'file' kind — EnvSource raises SecretNotFound (not AccessDenied)
        # so fall-through works. Let's force AccessDenied.
        # Construct a source that always raises AccessDenied
        class AlwaysDeny(ts.Source):
            def get(self, kind, key):
                raise ts.SecretAccessDenied("nope")
        c2 = ts.CompositeSource([AlwaysDeny()])
        with self.assertRaises(ts.SecretAccessDenied):
            c2.get("anything", "x")

    def test_add(self):
        c = ts.CompositeSource([ts.DictSource()])
        c.add(ts.DictSource({"x": "added"}))
        self.assertEqual(c.get("dict", "x"), "added")


class TestCachingSource(unittest.TestCase):
    def test_caches_within_ttl(self):
        # Count how many times the inner source is called
        counter = {"n": 0}

        class CountingSource(ts.Source):
            def get(self, kind, key):
                counter["n"] += 1
                return f"v{counter['n']}"

        cached = ts.CachingSource(CountingSource(), ttl_seconds=60)
        self.assertEqual(cached.get("dict", "a"), "v1")
        self.assertEqual(cached.get("dict", "a"), "v1")
        self.assertEqual(cached.get("dict", "a"), "v1")
        self.assertEqual(counter["n"], 1)

    def test_invalidate_clears(self):
        class CountingSource(ts.Source):
            def __init__(self):
                self.n = 0
            def get(self, kind, key):
                self.n += 1
                return f"v{self.n}"

        inner = CountingSource()
        cached = ts.CachingSource(inner, ttl_seconds=60)
        cached.get("dict", "a")
        cached.get("dict", "a")
        cached.invalidate()
        cached.get("dict", "a")
        self.assertEqual(inner.n, 2)

    def test_invalidate_specific_key(self):
        class CountingSource(ts.Source):
            def __init__(self):
                self.n = 0
            def get(self, kind, key):
                self.n += 1
                return f"v{self.n}"

        inner = CountingSource()
        cached = ts.CachingSource(inner, ttl_seconds=60)
        cached.get("dict", "a")
        cached.get("dict", "b")
        cached.invalidate(key="a")
        cached.get("dict", "a")  # re-fetch
        cached.get("dict", "b")  # cached
        self.assertEqual(inner.n, 3)


# ---------------------------------------------------------------------------
# Bulk loading
# ---------------------------------------------------------------------------


class TestBulkLoad(unittest.TestCase):
    def test_from_specs(self):
        results = ts.Secret.from_specs([
            "env:HOME",
        ], default="/tmp")
        self.assertIn("env:HOME", results)
        self.assertIsInstance(results["env:HOME"], ts.Secret)
        # Should have loaded from env
        self.assertNotEqual(results["env:HOME"].value, "/tmp")

    def test_from_specs_with_failures(self):
        results = ts.Secret.from_specs([
            "env:HOME",
            "env:DEFINITELY_NOT_SET_XYZ_999",
        ], default="fb")
        # env:HOME loads from real env
        self.assertIsInstance(results["env:HOME"], ts.Secret)
        # The second one falls back to default
        self.assertEqual(results["env:DEFINITELY_NOT_SET_XYZ_999"].value, "fb")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


class TestRedact(unittest.TestCase):
    def test_password_redacted(self):
        out = ts.redact("password=hunter2")
        self.assertNotIn("hunter2", out)
        self.assertIn("***", out)

    def test_pwd_redacted(self):
        out = ts.redact("pwd:abc123")
        self.assertNotIn("abc123", out)

    def test_token_redacted(self):
        out = ts.redact("api_token=xyz-token-value")
        self.assertNotIn("xyz-token-value", out)

    def test_api_key_redacted(self):
        out = ts.redact("API_KEY=AKIAEXAMPLE")
        self.assertNotIn("AKIAEXAMPLE", out)

    def test_no_match_unchanged(self):
        self.assertEqual(ts.redact("hello world"), "hello world")

    def test_private_key_redacted(self):
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
        out = ts.redact(text)
        self.assertNotIn("MIIEpAIBAAKCAQEA", out)
        self.assertIn("***", out)

    def test_non_string_passes_through(self):
        self.assertEqual(ts.redact(123), 123)
        self.assertEqual(ts.redact(None), None)


class TestIsSecretPattern(unittest.TestCase):
    def test_positive(self):
        self.assertTrue(ts.is_secret_pattern("password=hunter2"))
        self.assertTrue(ts.is_secret_pattern("api_key=AK"))

    def test_negative(self):
        self.assertFalse(ts.is_secret_pattern("hello world"))


class TestRedactingFormatter(unittest.TestCase):
    def test_redacts_message(self):
        fmt = ts.RedactingFormatter()
        # Make a fake log record
        class FakeRecord:
            def getMessage(self):
                return "connected with password=hunter2"
        msg = fmt.format(FakeRecord())
        self.assertNotIn("hunter2", msg)
        self.assertIn("***", msg)

    def test_with_logging_module(self):
        # Wire into stdlib logging
        logger = logging.getLogger("tiny_secret_test")
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ts.RedactingFormatter(logging.Formatter("%(message)s")))
        logger.addHandler(handler)
        try:
            # Use logger — we just check no exception is raised
            logger.info("password=supersecret")
        finally:
            logger.removeHandler(handler)


# ---------------------------------------------------------------------------
# End-to-end: full pipeline
# ---------------------------------------------------------------------------


class TestEndToEnd(unittest.TestCase):
    def test_full_pipeline(self):
        # 1. Register in dict
        d = ts.DictSource({"DB_PASSWORD": "db-secret-1", "API_KEY": "key-1"})
        composite = ts.CompositeSource([ts.EnvSource(), ts.FileSource(), d])
        cached = ts.CachingSource(composite, ttl_seconds=10)

        # 2. Load two secrets
        db = ts.Secret.from_spec("dict:DB_PASSWORD", sources=cached)
        api = ts.Secret.from_spec("dict:API_KEY", sources=cached)

        # 3. Verify they're loaded and equal (constant-time)
        self.assertEqual(db, "db-secret-1")
        self.assertEqual(api, "key-1")

        # 4. Verify repr doesn't leak
        self.assertNotIn("db-secret-1", repr(db))
        self.assertNotIn("key-1", repr(api))

        # 5. Verify format string doesn't leak
        log_line = f"connecting to db with password={db}"
        self.assertNotIn("db-secret-1", log_line)
        self.assertIn("***", log_line)

    def test_aws_source_no_creds_raises(self):
        # Strip AWS creds from env
        env_save = {}
        for k in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]:
            if k in os.environ:
                env_save[k] = os.environ[k]
                del os.environ[k]
        try:
            src = ts.AWSSource()
            with self.assertRaises(ts.SecretAccessDenied):
                src.get("aws", "test/secret")
        finally:
            for k, v in env_save.items():
                os.environ[k] = v

    def test_vault_source_no_addr_raises(self):
        # Strip Vault env
        env_save = {}
        for k in ["VAULT_ADDR", "VAULT_TOKEN"]:
            if k in os.environ:
                env_save[k] = os.environ[k]
                del os.environ[k]
        try:
            src = ts.VaultSource()
            with self.assertRaises(ts.SecretAccessDenied):
                src.get("vault", "x#y")
        finally:
            for k, v in env_save.items():
                os.environ[k] = v


if __name__ == "__main__":
    unittest.main(verbosity=2)
