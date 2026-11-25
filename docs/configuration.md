# Configuration

> Status: **Current** — this is the schema `YamlConfigLoader` parses and
> the one `examples/config/`, `docker-compose.yml` and
> `docs/deployment.md` use.

## 1. Configuration sources

Right now two sources exist:

1. `config.yaml` (path passed to `securesync daemon --config`, default
   `config.yaml` in the working directory)
2. Built-in defaults for every omitted key

Command-line flags and `SECURESYNC_*` environment variables are planned
but not implemented yet; the daemon only takes `--config`.

## 2. Schema (`config.yaml`)

```yaml
# "development", "testing" or "production". Selects the RuntimeProfile;
# only "production" is meaningfully wired today.
profile: "production"

# Omit (or null) to have a fresh UUID generated on first run.
device_id: null

storage:
  # Directory this device syncs. Every cross-peer file reference is
  # relative to this root.
  sync_directory: "/home/user/Documents"
  # SQLite metadata database (files, chunks, version history).
  database_path: "/home/user/.securesync/metadata.db"
  # Directory for the JSON chunk manifests (the ChunkRepository cache).
  chunk_repository_path: "/home/user/.securesync/chunks"
  # Chunk size in bytes; must match FixedSizeChunkingStrategy's default
  # unless you have a reason to change it.
  chunk_size: 4194304  # 4 MiB

network:
  # Handshake server port: peers connect here to authenticate and
  # negotiate session keys. The transfer and manifest ports are
  # exchanged as part of the signed handshake payload, so they do not
  # need to be adjacent or pre-agreed.
  port: 8080
  transfer_port: 8082
  manifest_port: 8083
  discovery_enabled: true
  mDNS_service_type: "_securesync._tcp.local."

# "DEBUG", "INFO", "WARNING", "ERROR"
log_level: "INFO"
```

Unknown keys are ignored for now (there is no strict validation yet,
see section 4), so a typo in a key fails silently by falling back to
the default. That is a known gap, listed here on purpose.

## 3. Environment variable mapping (planned)

Not implemented yet. The plan: variables mirror the YAML path,
uppercased with `_` separators, and a double underscore `__` separates
nesting levels — e.g. `SECURESYNC_NETWORK__TRANSFER_PORT=8084` would
override `network.transfer_port` (a single underscore stays available
inside a key name without ambiguity).

## 4. Validation

Validation at load time is not implemented yet: the loader currently
falls back to defaults for missing keys and trusts the types in the
file. A schema validator (pydantic or hand-rolled) with key-specific
error messages is a planned improvement; the loader will fail loudly
on an unusable file (missing/invalid YAML) but not yet on a
semantically wrong value.

## 5. Hot reload (planned)

Hot reload is not wired up yet; today a config change takes effect
after a restart. The plan is to watch `config.yaml` with the existing
filesystem-watcher infrastructure. Not every setting would be safely
hot-reloadable:

| Reloadable without restart | Requires restart |
|---|---|
| `storage.sync_directory` (add/remove roots) | `network.port` |
| `log_level` | `device_id` |

This table will be enforced in code (an attempt to hot-reload a
restart-only key logs a warning and is ignored, not silently
half-applied).
