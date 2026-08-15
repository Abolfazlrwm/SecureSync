"""Domain port for persistent device identity and signing.

Separate from :mod:`securesync.domain.crypto`'s X25519 key-exchange
port: X25519 keys there are ephemeral, generated fresh per handshake
for forward secrecy, and can't sign anything. `IdentityProvider` is
for a device's *long-term* identity — generated once, persisted, and
used to sign a handshake so the peer on the other end can verify it
really came from whoever holds that persistent key, and — via
:class:`TrustedPeerRepository` — that it's the *same* key that device
presented last time.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdentityKeyPair:
    """A device's long-term Ed25519 signing keypair.

    Attributes:
        private_key: Raw Ed25519 private key bytes. Never transmitted.
        public_key: Raw Ed25519 public key bytes. Safe to share —
            this is what a peer pins in :class:`TrustedPeerRepository`.
    """

    private_key: bytes
    public_key: bytes


class IdentityProvider(ABC):
    """Generates, persists, and uses a device's long-term identity keypair."""

    @abstractmethod
    def load_or_create(self) -> IdentityKeyPair:
        """Load this device's persisted identity, generating one if none exists.

        Returns:
            The (possibly newly created) `IdentityKeyPair`.
        """
        raise NotImplementedError

    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign `message` with `private_key`.

        Args:
            private_key: Raw Ed25519 private key bytes.
            message: The bytes to sign.

        Returns:
            The raw signature bytes.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify `signature` over `message` was produced by `public_key`'s private key.

        Args:
            public_key: Raw Ed25519 public key bytes.
            message: The bytes that were signed.
            signature: The signature to verify.

        Returns:
            True if the signature is valid, False otherwise. Never
            raises on an invalid signature — only a malformed key or
            signature (wrong length, wrong format) is an error.
        """
        raise NotImplementedError


class TrustedPeerRepository(ABC):
    """Persists which long-term public key each peer device ID is trusted at.

    This is what turns a per-handshake signature check into real
    trust-on-first-use protection: the *first* handshake with a given
    `device_id` pins its public key; every later handshake must
    present that same key, or something is impersonating that device
    (or its key genuinely rotated, which this repository can't
    distinguish from an attack on its own — see
    ``docs/adr/0019-peer-authentication-and-trust-on-first-use.md``).
    """

    @abstractmethod
    async def get_trusted_key(self, device_id: str) -> bytes | None:
        """Return the pinned public key for `device_id`, or None if never seen.

        Args:
            device_id: The peer device ID to look up.

        Returns:
            The pinned raw Ed25519 public key, or None if this is the
            first time `device_id` has been seen.
        """
        raise NotImplementedError

    @abstractmethod
    async def trust(self, device_id: str, public_key: bytes) -> None:
        """Pin `public_key` as trusted for `device_id`.

        Args:
            device_id: The peer device ID to pin a key for.
            public_key: The raw Ed25519 public key to pin.
        """
        raise NotImplementedError
