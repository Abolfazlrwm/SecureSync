"""Unit tests for YamlConfigLoader."""

import yaml

from securesync.domain.config import RuntimeProfile
from securesync.infrastructure.config.yaml_config_loader import YamlConfigLoader


def test_load_valid_config(tmp_path) -> None:
    config_data = {
        "profile": "development",
        "storage": {
            "sync_directory": "/tmp/sync",
            "database_path": "test.db",
        },
        "network": {
            "port": 9090,
        },
        "log_level": "DEBUG",
    }

    config_file = tmp_path / "config.yaml"
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)

    config = YamlConfigLoader.load(str(config_file))

    assert config.profile == RuntimeProfile.DEVELOPMENT
    assert config.storage.sync_directory == "/tmp/sync"
    assert config.storage.database_path == "test.db"
    assert config.network.port == 9090
    assert config.log_level == "DEBUG"


def test_load_minimal_config(tmp_path) -> None:
    config_file = tmp_path / "minimal.yaml"
    with open(config_file, "w") as f:
        f.write("")  # Empty file

    config = YamlConfigLoader.load(str(config_file))

    assert config.profile == RuntimeProfile.PRODUCTION
    assert config.network.port == 8080
    assert config.log_level == "INFO"
