"""Domain ports for End-to-End Encryption.

Defines the cryptographic contracts for key exchange and AEAD encryption,
following the design in docs/security.md.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Final

KEY_SIZE: Final = 32
NONCE_SIZE: Final = 12
TAG_SIZE: Final = 16


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """A payload encrypted with an AEAD cipher.

    Attributes:
        ciphertext: The encrypted data.
        nonce: The unique nonce used for this encryption.
        tag: The authentication tag.
    """

    ciphertext: bytes
    nonce: bytes
    tag: bytes


class KeyExchangeProvider(ABC):
    """Port for performing X25519 key exchange."""

    @abstractmethod
    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate a new X25519 private/public key pair."""
        raise NotImplementedError

    @abstractmethod
    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Derive a shared secret using ECDH."""
        raise NotImplementedError


class SessionKeyProvider(ABC):
    """Port for deriving session keys from a shared secret."""

    @abstractmethod
    def derive_session_keys(self, shared_secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
        """Derive (send_key, receive_key) using HKDF."""
        raise NotImplementedError


class AeadCipher(ABC):
    """Port for AEAD encryption (AES-GCM or ChaCha20-Poly1305)."""

    @abstractmethod
    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = b""
    ) -> EncryptedPayload:
        """Encrypt and authenticate plaintext."""
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt and verify an encrypted payload."""
        raise NotImplementedError
