"""Unit tests for Ed25519IdentityProvider."""

from __future__ import annotations

from pathlib import Path

from securesync.infrastructure.crypto.ed25519_identity_provider import Ed25519IdentityProvider


class TestLoadOrCreate:
    """Tests for identity generation and persistence."""

    def test_creates_a_new_identity_when_none_exists(self, tmp_path: Path) -> None:
        provider = Ed25519IdentityProvider(tmp_path)

        keypair = provider.load_or_create()

        assert len(keypair.private_key) == 32
        assert len(keypair.public_key) == 32

    def test_returns_the_same_identity_on_repeated_calls(self, tmp_path: Path) -> None:
        provider = Ed25519IdentityProvider(tmp_path)

        first = provider.load_or_create()
        second = provider.load_or_create()

        assert first.public_key == second.public_key
        assert first.private_key == second.private_key

    def test_persists_across_provider_instances(self, tmp_path: Path) -> None:
        first_provider = Ed25519IdentityProvider(tmp_path)
        original = first_provider.load_or_create()

        second_provider = Ed25519IdentityProvider(tmp_path)
        reloaded = second_provider.load_or_create()

        assert reloaded.public_key == original.public_key

    def test_different_storage_dirs_get_different_identities(self, tmp_path: Path) -> None:
        provider_a = Ed25519IdentityProvider(tmp_path / "a")
        provider_b = Ed25519IdentityProvider(tmp_path / "b")

        keypair_a = provider_a.load_or_create()
        keypair_b = provider_b.load_or_create()

        assert keypair_a.public_key != keypair_b.public_key


class TestSignAndVerify:
    """Tests for signing and signature verification."""

    def test_valid_signature_verifies(self, tmp_path: Path) -> None:
        provider = Ed25519IdentityProvider(tmp_path)
        keypair = provider.load_or_create()
        message = b"hello handshake"

        signature = provider.sign(keypair.private_key, message)

        assert provider.verify(keypair.public_key, message, signature) is True

    def test_tampered_message_fails_verification(self, tmp_path: Path) -> None:
        provider = Ed25519IdentityProvider(tmp_path)
        keypair = provider.load_or_create()
        signature = provider.sign(keypair.private_key, b"original message")

        assert provider.verify(keypair.public_key, b"tampered message", signature) is False

    def test_signature_from_a_different_key_fails_verification(self, tmp_path: Path) -> None:
        provider = Ed25519IdentityProvider(tmp_path)
        keypair_a = Ed25519IdentityProvider(tmp_path / "a").load_or_create()
        keypair_b = Ed25519IdentityProvider(tmp_path / "b").load_or_create()
        message = b"hello handshake"

        signature = provider.sign(keypair_a.private_key, message)

        assert provider.verify(keypair_b.public_key, message, signature) is False
