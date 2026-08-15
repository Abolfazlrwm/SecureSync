"""Cryptography.io (pyca) implementation of crypto ports."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securesync.domain.crypto import (
    AeadCipher,
    EncryptedPayload,
    KeyExchangeProvider,
    SessionKeyProvider,
)


class PycaKeyExchangeProvider(KeyExchangeProvider):
    """X25519 key exchange using cryptography.io."""

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate a new X25519 private/public key pair.

        Returns:
            A ``(private_key, public_key)`` tuple of raw bytes.
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (private_key.private_bytes_raw(), public_key.public_bytes_raw())

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Derive a shared secret using ECDH.

        Args:
            private_key: This side's raw X25519 private key bytes.
            peer_public_key: The peer's raw X25519 public key bytes.

        Returns:
            The raw ECDH shared secret bytes.
        """
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
        pub = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        return priv.exchange(pub)


class PycaSessionKeyProvider(SessionKeyProvider):
    """HKDF session key derivation using cryptography.io."""

    def derive_session_keys(self, shared_secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
        """Derive a ``(send_key, receive_key)`` pair from a shared secret using HKDF.

        Args:
            shared_secret: The ECDH shared secret from key exchange.
            salt: A per-session salt (e.g. a nonce exchanged during the
                handshake) so the same shared secret never derives the
                same key material twice.

        Returns:
            A ``(send_key, receive_key)`` tuple of 32-byte AEAD keys.

        Note:
            The two values returned here are not yet a directional
            ``(send_key, receive_key)`` pair — two peers with the same
            ``shared_secret``/``salt`` get the identical pair back.
            :class:`~securesync.infrastructure.networking.x25519_handshake.X25519Handshake`
            is what turns this into a real per-direction pair: it
            calls this method once per side and swaps the pair for
            whichever side is the responder, so each side's send key
            equals the other's receive key. Don't call this method
            directly and treat its output as already-directional.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for send_key, 32 for receive_key
            salt=salt,
            info=b"securesync-session-keys",
        )
        okm = hkdf.derive(shared_secret)
        return okm[:32], okm[32:]


class AesGcmCipher(AeadCipher):
    """AES-256-GCM implementation of AeadCipher."""

    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = b""
    ) -> EncryptedPayload:
        """Encrypt and authenticate plaintext with AES-256-GCM.

        Args:
            plaintext: The data to encrypt.
            key: A 32-byte AES-256 key.
            nonce: A 12-byte nonce, unique per key.
            associated_data: Additional data to authenticate but not encrypt.

        Returns:
            The resulting :class:`EncryptedPayload`.
        """
        aesgcm = AESGCM(key)
        # AESGCM.encrypt in cryptography.io includes the tag in the ciphertext
        data_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        tag = data_with_tag[-16:]
        ciphertext = data_with_tag[:-16]
        return EncryptedPayload(ciphertext, nonce, tag)

    def decrypt(self, payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt and verify an AES-256-GCM payload.

        Args:
            payload: The encrypted payload to decrypt.
            key: The same 32-byte key used to encrypt.
            associated_data: The same associated data passed to :meth:`encrypt`.

        Returns:
            The decrypted plaintext.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
        aesgcm = AESGCM(key)
        data_with_tag = payload.ciphertext + payload.tag
        return aesgcm.decrypt(payload.nonce, data_with_tag, associated_data)


class ChaCha20Cipher(AeadCipher):
    """ChaCha20-Poly1305 implementation of AeadCipher."""

    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = b""
    ) -> EncryptedPayload:
        """Encrypt and authenticate plaintext with ChaCha20-Poly1305.

        Args:
            plaintext: The data to encrypt.
            key: A 32-byte ChaCha20 key.
            nonce: A 12-byte nonce, unique per key.
            associated_data: Additional data to authenticate but not encrypt.

        Returns:
            The resulting :class:`EncryptedPayload`.
        """
        chacha = ChaCha20Poly1305(key)
        data_with_tag = chacha.encrypt(nonce, plaintext, associated_data)
        tag = data_with_tag[-16:]
        ciphertext = data_with_tag[:-16]
        return EncryptedPayload(ciphertext, nonce, tag)

    def decrypt(self, payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt and verify a ChaCha20-Poly1305 payload.

        Args:
            payload: The encrypted payload to decrypt.
            key: The same 32-byte key used to encrypt.
            associated_data: The same associated data passed to :meth:`encrypt`.

        Returns:
            The decrypted plaintext.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
        chacha = ChaCha20Poly1305(key)
        data_with_tag = payload.ciphertext + payload.tag
        return chacha.decrypt(payload.nonce, data_with_tag, associated_data)
