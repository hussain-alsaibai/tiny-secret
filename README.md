# tiny-secret

> Zero-dependency secret loader and redacting printer for Python. Loads from env, files, dicts, keyring, Vault, or AWS — and never leaks secrets to logs.

```bash
# coming soon
pip install tiny-secret
```

## Why?

`python-dotenv` only knows about `.env` files. `pydantic-settings` is heavy and locks you into pydantic. `boto3` is 80+ MB just to fetch one secret. Most teams re-implement this badly, and their logs leak passwords.

`tiny-secret`:

- Loads from `env:`, `file:`, `dict:`, `literal:`, `keyring:`, `vault:`, `aws:` (single uniform API)
- Wraps values in a `Secret` class that **hides the value from `repr`, `str`, and `format`**
- Ships a `redact()` function that auto-masks `password=…`, `api_key=…`, `token=…`, private keys in any log line
- Wires into stdlib `logging` via `RedactingFormatter`
- Implements AWS SigV4 by hand (no boto3)
- Talks to Vault over plain HTTPS (no hvac)
- 56 tests, 0 external deps

## Usage

### Load a secret

```python
import tiny_secret as ts

s = ts.Secret.from_spec("env:DB_PASSWORD")
print(s)            # "***"  (NEVER the actual value)
print(repr(s))      # "Secret('env:DB_PASSWORD')"
print(s.value)      # "hunter2"  (when you genuinely need it)
print(s.fingerprint) # "9f86d081"  (8-char SHA-256, safe to log)
```

### Composite sources

```python
# Try in order: in-memory dict → env → file
sources = ts.CompositeSource([
    ts.DictSource({"DB_PASSWORD": "dev-only"}),
    ts.EnvSource(),
    ts.FileSource(),
])

db = ts.Secret.from_spec("dict:DB_PASSWORD", sources=sources)
api = ts.Secret.from_spec("env:STRIPE_KEY", sources=sources, default="sk_test_...")
```

### Bulk load

```python
secrets = ts.Secret.from_specs([
    "env:DB_PASSWORD",
    "env:STRIPE_KEY",
    "file:/run/secrets/jwt",
], default="missing")

# Returns dict[str, Secret | SecretError]
```

### Redacting log formatter

```python
import logging
import tiny_secret as ts

handler = logging.StreamHandler()
handler.setFormatter(ts.RedactingFormatter(
    logging.Formatter("%(asctime)s %(message)s")
))
logger = logging.getLogger("app")
logger.addHandler(handler)

logger.info("Connecting with password=hunter2")
# "2026-07-02 09:00:00,001 Connecting with password=***"
```

### Redact arbitrary text

```python
from tiny_secret import redact

safe = redact("user=alice password=hunter2 token=AKIAEXAMPLE")
# "user=alice password=*** token=***"
```

## Source Specs

| Spec | Source | Example |
|---|---|---|
| `env:VAR` | `os.environ` | `env:DB_PASSWORD` |
| `file:/path` | file (with mode check) | `file:/run/secrets/db` |
| `dict:KEY` | in-memory | `dict:DB_PASSWORD` |
| `literal:NAME` | registered literal (opt-in) | `literal:dev-pwd` |
| `keyring:NAME` | OS keyring | `keyring:db/server` |
| `vault:PATH#FIELD` | Vault KV v2 | `vault:secret/data/db#password` |
| `aws:NAME[#JSON_KEY]` | AWS Secrets Manager | `aws:prod/db` |

## Caching

```python
cached = ts.CachingSource(sources, ttl_seconds=60)
db = ts.Secret.from_spec("env:DB_PASSWORD", sources=cached)
# ... 60s later, secret is fetched again

cached.invalidate()  # clear all
cached.invalidate(key="DB_PASSWORD")  # clear one
```

## What's in the box

| Component | LOC | Notes |
|---|---|---|
| `Secret` value object | ~80 | Repr/str/format hide value, fingerprint, constant-time eq |
| 7 sources | ~400 | env, file, dict, literal, keyring, vault, aws |
| `CompositeSource` | ~30 | First hit wins, `AccessDenied` bubbles |
| `CachingSource` | ~25 | TTL cache, `invalidate()` |
| `RedactingFormatter` | ~30 | Stdlib `logging` integration |
| `redact()` | ~10 | Pattern-based masking |

Total: **~580 LOC**, single file, zero required dependencies, 56 tests. (Optional: `keyring` is loaded only if installed.)

## Ecosystem

Part of the [tiny-* stack](https://github.com/hussain-alsaibai):

| Category | Repo |
|---|---|
| HTTP | [tiny-router](https://github.com/hussain-alsaibai/tiny-router) |
| Logging | [tiny-log](https://github.com/hussain-alsaibai/tiny-log) |
| Validation | [tiny-validator](https://github.com/hussain-alsaibai/tiny-validator) |
| Config | [tiny-config](https://github.com/hussain-alsaibai/tiny-config) |
| CLI | [tiny-cli](https://github.com/hussain-alsaibai/tiny-cli) |
| Cache | [fast-cache](https://github.com/hussain-alsaibai/fast-cache) |
| Rate | [tiny-rate](https://github.com/hussain-alsaibai/tiny-rate) |
| Retry | [tiny-retry](https://github.com/hussain-alsaibai/tiny-retry) |
| Pool | [tiny-pool](https://github.com/hussain-alsaibai/tiny-pool) |
| Compose | [tiny-compose](https://github.com/hussain-alsaibai/tiny-compose) |
| Trace | [tiny-trace](https://github.com/hussain-alsaibai/tiny-trace) |
| Secret | **tiny-secret** (this) |
| AI Agent | [tiny-agent](https://github.com/hussain-alsaibai/tiny-agent) |
| MCP | [tiny-mcp](https://github.com/hussain-alsaibai/tiny-mcp) |
| Embeddings | [tiny-embed](https://github.com/hussain-alsaibai/tiny-embed) |
| Storage | [snapdb](https://github.com/hussain-alsaibai/snapdb) |
| Cron | [tiny-cron](https://github.com/hussain-alsaibai/tiny-cron) |
| Flags | [tiny-flags](https://github.com/hussain-alsaibai/tiny-flags) |
| Queue | [tiny-queue](https://github.com/hussain-alsaibai/tiny-queue) |

## License

MIT — see [LICENSE](LICENSE).

## Today's siblings

- [`tiny-metrics`](https://github.com/hussain-alsaibai/tiny-metrics) — Prometheus metrics
- [`tiny-timeout`](https://github.com/hussain-alsaibai/tiny-timeout) — timeouts that work
- [`tiny-idempotency`](https://github.com/hussain-alsaibai/tiny-idempotency) — idempotency keys
