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
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return (private_key.private_bytes_raw(), public_key.public_bytes_raw())

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
        pub = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        return priv.exchange(pub)


class PycaSessionKeyProvider(SessionKeyProvider):
    """HKDF session key derivation using cryptography.io."""

    def derive_session_keys(self, shared_secret: bytes, salt: bytes) -> tuple[bytes, bytes]:
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
        aesgcm = AESGCM(key)
        # AESGCM.encrypt in cryptography.io includes the tag in the ciphertext
        data_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        tag = data_with_tag[-16:]
        ciphertext = data_with_tag[:-16]
        return EncryptedPayload(ciphertext, nonce, tag)

    def decrypt(self, payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
        aesgcm = AESGCM(key)
        data_with_tag = payload.ciphertext + payload.tag
        return aesgcm.decrypt(payload.nonce, data_with_tag, associated_data)


class ChaCha20Cipher(AeadCipher):
    """ChaCha20-Poly1305 implementation of AeadCipher."""

    def encrypt(
        self, plaintext: bytes, key: bytes, nonce: bytes, associated_data: bytes = b""
    ) -> EncryptedPayload:
        chacha = ChaCha20Poly1305(key)
        data_with_tag = chacha.encrypt(nonce, plaintext, associated_data)
        tag = data_with_tag[-16:]
        ciphertext = data_with_tag[:-16]
        return EncryptedPayload(ciphertext, nonce, tag)

    def decrypt(self, payload: EncryptedPayload, key: bytes, associated_data: bytes = b"") -> bytes:
        chacha = ChaCha20Poly1305(key)
        data_with_tag = payload.ciphertext + payload.tag
        return chacha.decrypt(payload.nonce, data_with_tag, associated_data)
