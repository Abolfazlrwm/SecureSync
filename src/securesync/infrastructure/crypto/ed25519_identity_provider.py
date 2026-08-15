"""Ed25519 implementation of the IdentityProvider port.

Persists a device's long-term signing keypair as two raw-byte files
on disk, generating them once on first use. Separate from
:class:`~securesync.infrastructure.crypto.pyca_crypto.PycaKeyExchangeProvider`
(X25519, ephemeral, never persisted) — see ``domain/identity.py``'s
module docstring for why these are different key types for different
purposes.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from securesync.domain.identity import IdentityKeyPair, IdentityProvider


class Ed25519IdentityProvider(IdentityProvider):
    """Persists a device's Ed25519 identity keypair as files under `storage_dir`."""

    def __init__(self, storage_dir: Path) -> None:
        """Initialize the provider.

        Args:
            storage_dir: Directory the keypair is stored in (created
                if missing). File permissions on the private key are
                restricted to the owner where the platform supports it.
        """
        self._private_key_path = storage_dir / "identity.private"
        self._public_key_path = storage_dir / "identity.public"

    def load_or_create(self) -> IdentityKeyPair:
        """Load this device's persisted identity, generating one if none exists.

        Returns:
            The (possibly newly created) `IdentityKeyPair`.
        """
        if self._private_key_path.exists() and self._public_key_path.exists():
            return IdentityKeyPair(
                private_key=self._private_key_path.read_bytes(),
                public_key=self._public_key_path.read_bytes(),
            )

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        keypair = IdentityKeyPair(
            private_key=private_key.private_bytes_raw(),
            public_key=public_key.public_bytes_raw(),
        )
        self._persist(keypair)
        return keypair

    def _persist(self, keypair: IdentityKeyPair) -> None:
        """Write the keypair to disk, restricting the private key to owner-readable."""
        self._private_key_path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key_path.write_bytes(keypair.private_key)
        with contextlib.suppress(PermissionError):
            os.chmod(self._private_key_path, 0o600)
        self._public_key_path.write_bytes(keypair.public_key)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign `message` with `private_key`.

        Args:
            private_key: Raw Ed25519 private key bytes.
            message: The bytes to sign.

        Returns:
            The raw signature bytes.
        """
        return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify `signature` over `message` was produced by `public_key`'s private key.

        Args:
            public_key: Raw Ed25519 public key bytes.
            message: The bytes that were signed.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise.
        """
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except InvalidSignature:
            return False
