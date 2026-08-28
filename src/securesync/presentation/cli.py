"""Command-line interface for SecureSync.

Provides ``securesync <command>`` entry points for managing configuration,
viewing peer status, and triggering sync operations. Built on Typer
(type-hint driven, Click-compatible).

Usage:
    securesync config            # Show current configuration
    securesync peers             # List discovered peers
    securesync sync [path...]    # Sync specified files (push)
    securesync pull [path...]    # Pull specified files from a peer
    securesync init              # Generate a new identity keypair
    securesync trust <device>    # Reset trust for a peer device
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import structlog
import typer
import yaml

app = typer.Typer(help="SecureSync — encrypted peer-to-peer file synchronization")

logger = structlog.get_logger(__name__)


def _load_config() -> dict[str, Any]:
    """Load the user's YAML config, returning an empty dict if missing."""
    config_paths = [
        Path.home() / ".securesync" / "config.yaml",
        Path.cwd() / "config.yaml",
    ]
    for path in config_paths:
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f) or {}
    return {}


@app.command()
def config(
    show_keys: bool = typer.Option(False, "--show-keys", help="Show secret key paths in config"),
) -> None:
    """Display the current configuration."""
    cfg = _load_config()
    if not cfg:
        typer.echo("No config file found. Run 'securesync init' to get started.")
        raise typer.Exit(1)

    # Redact sensitive fields by default
    redacted = dict(cfg)
    if not show_keys and "device_id" in redacted:
        redacted["device_id"] = redacted["device_id"][:4] + "..."

    typer.echo(json.dumps(redacted, indent=2, default=str))


@app.command()
def peers() -> None:
    """List discovered peers (from the in-memory peer repository)."""
    # This is a lightweight informational command — it reads what the
    # background daemon would have discovered. In a future phase, this
    # would query a running daemon via a Unix socket.
    typer.echo("No running SecureSync daemon detected.")
    typer.echo("Start the daemon with: securesync daemon")
    typer.echo()
    typer.echo("Known peers (from trusted_peers.json, no connectivity check):")
    storage = Path.home() / ".securesync"
    trust_file = storage / "trusted_peers.json"
    if trust_file.exists():
        peers = json.loads(trust_file.read_text())
        for device_id, key_hex in peers.items():
            typer.echo(f"  {device_id}: {key_hex[:8]}...")
    else:
        typer.echo("  (no trusted peers configured)")


@app.command()
def sync(
    # typer's documented pattern requires the Argument() call here, in
    # default-argument position — it's how typer discovers the CLI spec.
    paths: list[str] = typer.Argument(  # noqa: B008
        None, help="Files or directories to sync (default: entire sync root)"
    ),
) -> None:
    """Push local files to all discovered peers."""
    if not paths:
        typer.echo("Syncing entire sync root...")
    for p in paths:
        typer.echo(f"  Would sync: {p}")
    typer.echo("NOTE: Automatic sync requires the daemon to be running.")
    typer.echo("Run: securesync daemon")


@app.command()
def pull(
    paths: list[str] = typer.Argument(..., help="Files to pull from a peer"),  # noqa: B008
    from_device: str = typer.Option(None, "--from", help="Specific peer device ID"),
) -> None:
    """Pull files from a peer."""
    for p in paths:
        typer.echo(f"  Would pull {p}" + (f" from {from_device}" if from_device else ""))


@app.command()
def init(
    storage_dir: str = typer.Option("~/.securesync", "--storage-dir",
                                     help="Directory to store config and identity"),
) -> None:
    """Generate a new device identity and default config."""
    from securesync.domain.identity import IdentityKeyPair
    from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider

    resolved = Path(storage_dir).expanduser()
    resolved.mkdir(parents=True, exist_ok=True)

    identity_provider = Ed25519IdentityProvider(resolved)
    keypair: IdentityKeyPair = identity_provider.load_or_create()

    config = {
        "device_id": "auto",
        "profile": "production",
        "storage": {
            "sync_directory": str(resolved / "sync"),
            "database_path": str(resolved / "metadata.db"),
            "chunk_repository_path": str(resolved / "chunks"),
            "chunk_size": 4194304,
        },
        "network": {
            "port": 8080,
            "transfer_port": 8082,
            "manifest_port": 8083,
            "discovery_enabled": True,
            "mDNS_service_type": "_securesync._tcp.local.",
        },
        "log_level": "INFO",
    }

    config_path = resolved / "config.yaml"
    config_path.write_text(yaml.dump(config, default_flow_style=False))

    typer.echo(f"Identity generated and saved to: {resolved / 'identity.private'}")
    typer.echo(f"Config written to: {config_path}")
    typer.echo(f"Fingerprint: {keypair.public_key.hex()[:16]}")


@app.command()
def trust(
    device_id: str = typer.Argument(..., help="Device ID to reset trust for"),
    storage_dir: str = typer.Option("~/.securesync", "--storage-dir",
                                     help="Directory containing config and identity"),
) -> None:
    """Reset trust for a previously-seen peer device."""
    import json as _json

    resolved = Path(storage_dir).expanduser()
    trust_file = resolved / "trusted_peers.json"

    if not trust_file.exists():
        typer.echo("No trusted peers file found.")
        raise typer.Exit(1)

    peers = _json.loads(trust_file.read_text())
    if device_id not in peers:
        typer.echo(f"Device {device_id!r} is not in the trust store.")
        raise typer.Exit(1)

    del peers[device_id]
    trust_file.write_text(_json.dumps(peers, indent=2, sort_keys=True))
    typer.echo(f"Trust reset for device: {device_id}")


@app.command()
def daemon(
    config_path: str = typer.Option("config.yaml", "--config", "-c",
                                    help="Path to config file"),
) -> None:
    """Start the SecureSync synchronization daemon."""
    from securesync.main import bootstrap

    try:
        asyncio.run(bootstrap(config_path))
    except KeyboardInterrupt:
        typer.echo("\nShutting down...")
    except Exception as e:
        logger.error("daemon_failed", error=str(e))
        typer.echo(f"Error: {e}", err=True)
        sys.exit(1)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, "--version", "-V", help="Show version and exit"
    ),
) -> None:
    """SecureSync — encrypted peer-to-peer file synchronization."""
    if version:
        from importlib.metadata import version as get_version

        try:
            v = get_version("securesync")
            typer.echo(f"securesync {v}")
        except Exception:
            typer.echo("securesync (version unknown)")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        typer.echo("Run 'securesync <command> --help' for command-specific help.")
