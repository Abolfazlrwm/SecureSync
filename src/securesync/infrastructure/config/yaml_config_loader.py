"""Infrastructure for loading configuration from YAML files and environment."""

from __future__ import annotations

import os

import yaml

from securesync.domain.config import Configuration, NetworkConfig, RuntimeProfile, StorageConfig


class YamlConfigLoader:
    """Loads and merges configuration from multiple sources."""

    @staticmethod
    def load(path: str) -> Configuration:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            A populated Configuration object.
        """
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        # Extract sections
        storage_data = data.get("storage", {})
        network_data = data.get("network", {})

        storage = StorageConfig(
            sync_directory=storage_data.get("sync_directory", os.getcwd()),
            database_path=storage_data.get("database_path", "metadata.db"),
            chunk_repository_path=storage_data.get("chunk_repository_path", "chunks"),
        )

        network = NetworkConfig(
            port=network_data.get("port", 8080),
            discovery_enabled=network_data.get("discovery_enabled", True),
            mDNS_service_type=network_data.get("mDNS_service_type", "_securesync._tcp.local."),
            transfer_port=network_data.get("transfer_port", 8082),
            manifest_port=network_data.get("manifest_port", 8083),
        )

        return Configuration(
            profile=RuntimeProfile(data.get("profile", "production")),
            storage=storage,
            network=network,
            device_id=data.get("device_id"),
            log_level=data.get("log_level", "INFO"),
        )
