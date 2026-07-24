# Configuration

> Status: **Design** — implemented in Phase 10. Documented now so
> `config.yaml` references in the Dockerfile, docker-compose.yml, and
> `docs/deployment.md` point at a settled schema.

## 1. Configuration sources, in precedence order (highest wins)

1. Command-line flags (e.g. `securesync daemon --port 22001`)
2. Environment variables, prefixed `SECURESYNC_` (e.g. `SECURESYNC_PORT=22001`)
3. `config.yaml` file
4. Built-in defaults

## 2. Planned schema (`config.yaml`)

```yaml
device:
  id: auto          # auto-generated on first run if omitted
  name: "my-laptop"

sync:
  folders:
    - path: "/home/user/Documents"
      ignore:
        - "*.tmp"
        - ".DS_Store"
    - path: "/home/user/Photos"

network:
  discovery:
    udp_broadcast: true
    mdns: true
    broadcast_port: 21027
  transfer:
    listen_port: 22000
    max_parallel_transfers: 4
    compression: true

security:
  cipher: "aes-256-gcm"       # or "chacha20-poly1305"
  key_rotation:
    max_bytes: 10_000_000_000  # rotate session key every 10GB
    max_age_seconds: 3600
  require_authorization: true  # never auto-trust a new peer

reconnect:
  backoff:
    base_seconds: 1
    multiplier: 2
    max_seconds: 60
  heartbeat_interval_seconds: 10

logging:
  level: "info"
  format: "json"
```

## 3. Environment variable mapping

Environment variables mirror the YAML path, uppercased with `_` separators:
`SECURESYNC_NETWORK__TRANSFER__LISTEN_PORT=22001` overrides
`network.transfer.listen_port`. (Double underscore `__` separates nesting
levels — chosen so a single underscore remains available inside a key name
without ambiguity.)

## 4. Validation

Config is validated at load time (planned: via `pydantic` or a hand-rolled
schema validator — the specific choice is an open decision for Phase 10,
to be recorded as an ADR). Validation failures must name the exact
offending key and expected type/range, not a generic parse error.

## 5. Hot reload

`config.yaml` is watched (reusing the Phase 1 Filesystem Watcher
infrastructure) for changes. Not every setting is safely hot-reloadable:

| Reloadable without restart | Requires restart |
|---|---|
| `sync.folders` (add/remove) | `network.transfer.listen_port` |
| `logging.level` | `security.cipher` (mid-session cipher changes are unsafe) |
| `reconnect.*` | `device.id` |

This table is authoritative and will be enforced in code (an attempt to
hot-reload a restart-only key logs a warning and is ignored, not silently
half-applied).
