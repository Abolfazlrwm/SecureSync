"""Domain entities for the configuration system."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class RuntimeProfile(StrEnum):
    """Execution profiles for different environments."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class NetworkConfig:
    """Network-related configuration."""

    port: int = 8080
    discovery_enabled: bool = True
    mDNS_service_type: str = "_securesync._tcp.local."
    transfer_port: int = 8082
    manifest_port: int = 8083


@dataclass(frozen=True, slots=True)
class StorageConfig:
    """Storage-related configuration."""

    sync_directory: str
    database_path: str = "metadata.db"
    chunk_repository_path: str = "chunks"
    # Mirrors FixedSizeChunkingStrategy's own default (streaming_chunk_reader.py).
    # Duplicated as a plain literal rather than imported, since domain code
    # must not depend on infrastructure — see ADR-0001.
    chunk_size: int = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Configuration:
    """Root configuration object for the SecureSync application."""

    profile: RuntimeProfile
    storage: StorageConfig
    network: NetworkConfig = field(default_factory=NetworkConfig)
    device_id: str | None = None
    log_level: str = "INFO"
