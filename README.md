<div align="center">
<img src="assets/logo.svg" width="120" height="120" alt="SecureSync logo">

# SecureSync

**Encrypted peer-to-peer file synchronization engine.**

[![CI](https://github.com/Abolfazlrwm/SecureSync/actions/workflows/ci.yml/badge.svg)](https://github.com/Abolfazlrwm/SecureSync/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)]()
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-inspired-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![Tests](https://img.shields.io/badge/tests-413%20passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-93%25-brightgreen)]()
[![Status](https://img.shields.io/badge/status-Phase_21_%E2%80%94_push_receiver-green)]()

</div>

> ✅ **Project status:** Phases 0-21 are fully implemented.
> SecureSync performs real, fully autonomous, bidirectional
> peer-to-peer file sync end to end — verified by
> [tests/integration/test_end_to_end_sync.py](tests/integration/test_end_to_end_sync.py),
> which runs two real instances over real TCP and confirms a file
> created on one device is reconstructed correctly on the other, with
> no manual intervention. See [ROADMAP.md](ROADMAP.md) for the full
> implementation history and [docs/adr/](docs/adr/) for 26 ADRs
> documenting every real bug found and fixed along the way.

---

## Table of Contents

- [What is SecureSync?](#what-is-securesync)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Benchmarks](#benchmarks)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security](#security)
- [Community](#community)
- [License](#license)

## What is SecureSync?

SecureSync is a peer-to-peer file synchronization engine: devices discover
each other on the network, establish an authenticated end-to-end encrypted
channel, and synchronize only the parts of files that actually changed. No
central server holds your data.

## Architecture

SecureSync is built with Clean Architecture — domain logic is fully isolated
from infrastructure (filesystem, network, database), which keeps the core
sync/conflict-resolution logic testable and every adapter (transport, cipher,
discovery mechanism) independently swappable.

Full write-up: [docs/architecture.md](docs/architecture.md)

```mermaid
flowchart LR
    A[Filesystem Watcher] --> B[Chunk Engine]
    B --> C[Delta Sync]
    C --> D[Transfer Engine]
    D <--> E[Peer Discovery]
    D --> F[End-to-End Encryption]
    C --> G[Conflict Resolution]
    C --> H[(Metadata DB)]
```

## Features

- [x] Real-time filesystem watching (create/modify/delete/rename/move)
- [x] Streaming, bounded-memory chunking + SHA-256 hashing
- [x] Delta synchronization: content-hash comparison against a recorded baseline
- [x] Peer discovery (mDNS via zeroconf)
- [x] TCP transfers with AEAD-encrypted binary wire protocol
- [x] End-to-end encryption: X25519 key exchange, AES-256-GCM / ChaCha20-Poly1305
- [x] Trust-on-first-use peer authentication (Ed25519 identity signing)
- [x] Conflict resolution with version vectors and pluggable strategies
- [x] SQLite-backed metadata store (files, chunks, version history)
- [x] Synchronization Orchestrator with state machine and lifecycle control
- [x] Version-aware sync direction (PUSH / PULL / CONFLICT / NOOP)
- [x] Autonomous push receiver: an unsolicited pushed file is drained
      and reconstructed automatically, with no manual intervention
- [x] CLI entry point (`securesync` init / config / peers / sync / pull / daemon) — 100% test coverage
- [x] YAML configuration and production bootstrap with signal handling
      (with a graceful fallback on platforms where `asyncio` doesn't
      support signal handlers, e.g. Windows)
- [x] Verified end-to-end: two real instances, real TCP, real crypto —
      not just unit tests in isolation (see [tests/integration/test_end_to_end_sync.py](tests/integration/test_end_to_end_sync.py))

## Installation

```bash
git clone https://github.com/Abolfazlrwm/SecureSync.git
cd SecureSync
pip install -e ".[dev]"
```

## Quick Start

```bash
# Initialize a new device identity and default config
securesync init --storage-dir ~/.securesync

# Show current configuration (secrets redacted by default)
securesync config

# List known peers and their trust status
securesync peers

# Start the sync daemon (discovers peers, syncs automatically)
securesync daemon

# Push specific files/directories to all discovered peers
securesync sync path/to/file.txt

# Pull a file from a specific peer
securesync pull path/to/file.txt --from <peer-device-id>

# Reset trust for a peer (e.g. after a key rotation)
securesync trust <peer-device-id>
```

## Configuration

The YAML configuration system is fully implemented. The schema and all
available options are documented in
[docs/configuration.md](docs/configuration.md). Key sections: `storage`
(sync directory, database path, chunk size), `network` (handshake,
transfer, and manifest ports), `device_id` (auto-generated if omitted),
and `log_level` (default: `INFO`). See also
[examples/config](examples/config) for working example files.

## Documentation

| Doc | Covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Clean Architecture layers, SOLID, design patterns, tech decisions, diagrams |
| [docs/networking.md](docs/networking.md) | Peer discovery, topology, connection lifecycle |
| [docs/protocol.md](docs/protocol.md) | Binary wire protocol: header layout, packet types, handshake |
| [docs/security.md](docs/security.md) | Cryptographic design and full threat model |
| [docs/performance.md](docs/performance.md) | Benchmark methodology and metrics tracked |
| [docs/development.md](docs/development.md) | Local dev setup, testing conventions |
| [docs/deployment.md](docs/deployment.md) | Docker, docker-compose, systemd, ports |
| [docs/configuration.md](docs/configuration.md) | YAML schema, environment variables, hot reload |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common issues and diagnostics |
| [docs/adr/](docs/adr/) | Architecture Decision Records |

## Benchmarks

Benchmarks for chunking, hashing, encryption, and networking are implemented — see
[benchmarks/](benchmarks/). Methodology is defined in [docs/performance.md](docs/performance.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full phase-by-phase plan.

## FAQ

**Why not just use Syncthing?**
SecureSync is an educational, ground-up implementation built to demonstrate
architecture, networking, and cryptography engineering practices.

**Is the cryptography audited?**
SecureSync only uses well-established primitives from the audited `cryptography`
(pyca) library. The *composition* of those primitives into a protocol is not
independently audited.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow,
coding standards, and commit conventions.

## Security

See [SECURITY.md](SECURITY.md) for how to privately report a
vulnerability, and [docs/security.md](docs/security.md) for the full
cryptographic design and threat model.

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Issue templates](.github/ISSUE_TEMPLATE/) — bug reports and feature requests
- [Pull request template](.github/PULL_REQUEST_TEMPLATE.md)
- [Architecture Decision Records](docs/adr/) — the "why" behind every major decision

## License

[MIT](LICENSE)
