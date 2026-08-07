"""Unit tests for Pyca crypto adapters."""

import pytest

from securesync.domain.crypto import EncryptedPayload
from securesync.infrastructure.crypto.pyca_crypto import (
    AesGcmCipher,
    ChaCha20Cipher,
    PycaKeyExchangeProvider,
    PycaSessionKeyProvider,
)


def test_key_exchange_derives_same_secret() -> None:
    provider = PycaKeyExchangeProvider()

    priv_a, pub_a = provider.generate_key_pair()
    priv_b, pub_b = provider.generate_key_pair()

    secret_a = provider.derive_shared_secret(priv_a, pub_b)
    secret_b = provider.derive_shared_secret(priv_b, pub_a)

    assert secret_a == secret_b
    assert len(secret_a) == 32


def test_session_key_derivation() -> None:
    provider = PycaSessionKeyProvider()
    secret = b"a" * 32
    salt = b"s" * 16

    key1, key2 = provider.derive_session_keys(secret, salt)

    assert len(key1) == 32
    assert len(key2) == 32
    assert key1 != key2


@pytest.mark.parametrize("cipher_class", [AesGcmCipher, ChaCha20Cipher])
def test_aead_encryption_decryption(cipher_class) -> None:
    cipher = cipher_class()
    key = b"k" * 32
    nonce = b"n" * 12
    plaintext = b"Hello, SecureSync!"
    ad = b"associated data"

    payload = cipher.encrypt(plaintext, key, nonce, ad)

    assert isinstance(payload, EncryptedPayload)
    assert payload.ciphertext != plaintext
    assert len(payload.tag) == 16

    decrypted = cipher.decrypt(payload, key, ad)
    assert decrypted == plaintext


@pytest.mark.parametrize("cipher_class", [AesGcmCipher, ChaCha20Cipher])
def test_aead_decryption_fails_with_wrong_key(cipher_class) -> None:
    cipher = cipher_class()
    key = b"k" * 32
    wrong_key = b"w" * 32
    nonce = b"n" * 12
    plaintext = b"secret"

    payload = cipher.encrypt(plaintext, key, nonce)

    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        cipher.decrypt(payload, wrong_key)
