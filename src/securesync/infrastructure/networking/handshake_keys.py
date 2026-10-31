"""Key schedule and key-confirmation MACs for the v3 (SIGMA-style) handshake.

Everything here is derived from material that *both* sides hold, so nothing in
this module is transmitted. The schedule is normative in
``docs/design/1e-handshake.md`` §4.7:

```text
ss         = X25519(e_i_priv, e_r)
master     = HKDF(ss, salt = lp(n_i) ‖ lp(n_r),
                  info = lp("securesync-1e-master") ‖ t2)
k_r        = HKDF(master, lp("securesync-1e-kr"))
k_i        = HKDF(master, lp("securesync-1e-ki"))
session_id = HKDF(master, lp("securesync-1e-sid"), length = 8)
common     = lp(id_i) ‖ lp(id_r) ‖ session_id ‖ lp(e_i) ‖ lp(e_r)
i2r_key    = HKDF(master, lp("securesync-1e-i2r") ‖ common)
r2i_key    = HKDF(master, lp("securesync-1e-r2i") ‖ common)
```

Two properties are load-bearing and both are tested:

* ``master`` binds ``t2`` — the hash of messages 1 and 2 — so a party that
  cannot reproduce the exact transcript bytes cannot derive the same keys, even
  if it somehow obtained the ECDH output.
* ``k_r`` and ``k_i`` are **separate** confirmation keys. With a single shared
  key, an attacker could reflect the responder's ``mac_r`` back as ``mac_i``;
  with two, a reflected MAC simply fails to verify. ``mac_f`` reuses ``k_r``
  but over a transcript that already contains ``t_final`` *and* the accept
  label, so it cannot be confused with ``mac_r`` either.

The directional keys keep the 1d shape, so
:func:`~securesync.infrastructure.networking.session_keys.derive_directional_keys`
is reused verbatim with the new ``master`` and ``session_id``; that keeps the
frame layer's reflection protection intact across the handshake change.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securesync.core.protocol import ProtocolError
from securesync.infrastructure.networking.handshake_messages import (
    MAC_SIZE,
    NONCE_SIZE,
    HelloMessage,
    ReplyMessage,
)
from securesync.infrastructure.networking.replay_protection import (
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    SESSION_ID_SIZE,
)
from securesync.infrastructure.networking.session_keys import (
    KEY_SIZE,
    SessionKeys,
    derive_directional_keys,
    length_prefixed,
)
from securesync.infrastructure.networking.x25519_safety import (
    X25519_KEY_SIZE,
    check_shared_secret,
)

#: HKDF output length for the master secret and the confirmation keys.
SECRET_SIZE: Final = 32

#: Length of a SHA-256 transcript hash.
TRANSCRIPT_SIZE: Final = 32

_MASTER_INFO: Final = b"securesync-1e-master"
_RESPONDER_CONFIRM_INFO: Final = b"securesync-1e-kr"
_INITIATOR_CONFIRM_INFO: Final = b"securesync-1e-ki"
_SESSION_ID_INFO: Final = b"securesync-1e-sid"


class HandshakeKeyError(ProtocolError):
    """Raised when the v3 key schedule cannot derive session material."""


class KeyConfirmationError(ProtocolError):
    """Raised when a key-confirmation MAC does not verify."""


@dataclass(frozen=True, slots=True)
class HandshakeSecrets:
    """Every secret the v3 handshake derives, before role-based selection.

    Both peers compute the identical value; only
    :func:`keys_for_role` differs between them.

    Attributes:
        master: The per-handshake master secret, bound to the transcript.
        responder_confirmation_key: ``k_r``, used for ``mac_r`` and ``mac_f``.
        initiator_confirmation_key: ``k_i``, used for ``mac_i``.
        session_id: The 8-byte session identifier for the frame layer.
        initiator_to_responder_key: The initiator's send key.
        responder_to_initiator_key: The responder's send key.
    """

    master: bytes
    responder_confirmation_key: bytes
    initiator_confirmation_key: bytes
    session_id: bytes
    initiator_to_responder_key: bytes
    responder_to_initiator_key: bytes


def _hkdf(secret: bytes, salt: bytes, info: bytes, length: int = SECRET_SIZE) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(secret)


def _require_size(value: bytes, name: str, size: int) -> None:
    if len(value) != size:
        raise HandshakeKeyError(f"{name} must be {size} bytes, got {len(value)}")


def derive_handshake_secrets(
    *,
    shared_secret: bytes,
    hello: HelloMessage,
    reply: ReplyMessage,
    transcript_t2: bytes,
) -> HandshakeSecrets:
    """Derive the master secret, confirmation keys and frame keys.

    Args:
        shared_secret: The X25519 output. All-zero output is rejected, which
            catches the low-order public keys that produce it.
        hello: The decoded message 1 (supplies ``id_i``, ``e_i`` and ``n_i``).
        reply: The decoded message 2 (supplies ``id_r``, ``e_r`` and ``n_r``).
        transcript_t2: ``H(T1 ‖ lp(m1) ‖ lp(m2body))``, binding both messages.

    Returns:
        The :class:`HandshakeSecrets` for this handshake.

    Raises:
        LowOrderPointError: If ``shared_secret`` is all zero.
        HandshakeKeyError: If any input has the wrong length.
    """
    _require_size(shared_secret, "shared_secret", X25519_KEY_SIZE)
    check_shared_secret(shared_secret)
    _require_size(transcript_t2, "transcript_t2", TRANSCRIPT_SIZE)
    _require_size(hello.n_i, "hello.n_i", NONCE_SIZE)
    _require_size(reply.n_r, "reply.n_r", NONCE_SIZE)

    salt = length_prefixed(hello.n_i) + length_prefixed(reply.n_r)
    master = _hkdf(shared_secret, salt, length_prefixed(_MASTER_INFO) + transcript_t2)

    responder_confirmation_key = _hkdf(master, b"", length_prefixed(_RESPONDER_CONFIRM_INFO))
    initiator_confirmation_key = _hkdf(master, b"", length_prefixed(_INITIATOR_CONFIRM_INFO))
    session_id = _hkdf(master, b"", length_prefixed(_SESSION_ID_INFO), length=SESSION_ID_SIZE)

    i2r_key, r2i_key = derive_directional_keys(
        master,
        initiator_id=hello.device_id,
        responder_id=reply.device_id,
        session_id=session_id,
        initiator_ephemeral_pub=hello.e_i,
        responder_ephemeral_pub=reply.e_r,
    )
    return HandshakeSecrets(
        master=master,
        responder_confirmation_key=responder_confirmation_key,
        initiator_confirmation_key=initiator_confirmation_key,
        session_id=session_id,
        initiator_to_responder_key=i2r_key,
        responder_to_initiator_key=r2i_key,
    )


def keys_for_role(secrets: HandshakeSecrets, role: int) -> SessionKeys:
    """Select this device's send/receive keys from the derived material.

    Args:
        secrets: The output of :func:`derive_handshake_secrets`.
        role: :data:`ROLE_INITIATOR` or :data:`ROLE_RESPONDER` for this device.

    Returns:
        The :class:`SessionKeys` the frame layer expects.

    Raises:
        HandshakeKeyError: If ``role`` is neither known role.
    """
    _require_size(secrets.session_id, "session_id", SESSION_ID_SIZE)
    if role == ROLE_INITIATOR:
        return SessionKeys(
            session_id=secrets.session_id,
            send_key=secrets.initiator_to_responder_key,
            receive_key=secrets.responder_to_initiator_key,
            role=role,
        )
    if role == ROLE_RESPONDER:
        return SessionKeys(
            session_id=secrets.session_id,
            send_key=secrets.responder_to_initiator_key,
            receive_key=secrets.initiator_to_responder_key,
            role=role,
        )
    raise HandshakeKeyError(f"invalid role {role!r}")


def confirmation_mac(key: bytes, transcript: bytes) -> bytes:
    """Compute ``HMAC-SHA256(key, transcript)``.

    The transcript is always a hash already bound to the messages it covers, so
    no extra prefix is needed here.

    Args:
        key: ``k_r``, ``k_i``, or (for ``mac_f``) ``k_r`` again.
        transcript: The transcript hash to authenticate.

    Returns:
        Exactly :data:`MAC_SIZE` bytes.

    Raises:
        HandshakeKeyError: If ``key`` is not :data:`KEY_SIZE` bytes or
            ``transcript`` is not :data:`TRANSCRIPT_SIZE` bytes.
    """
    _require_size(key, "confirmation key", KEY_SIZE)
    _require_size(transcript, "transcript", TRANSCRIPT_SIZE)
    return hmac.new(key, transcript, "sha256").digest()


def verify_confirmation_mac(key: bytes, transcript: bytes, received: bytes) -> None:
    """Check a received confirmation MAC in constant time.

    Args:
        key: The confirmation key for the expected sender.
        transcript: The transcript hash the sender should have authenticated.
        received: The MAC as received on the wire.

    Raises:
        HandshakeKeyError: If any argument has the wrong length.
        KeyConfirmationError: If the MAC does not match.
    """
    _require_size(received, "confirmation mac", MAC_SIZE)
    expected = confirmation_mac(key, transcript)
    if not hmac.compare_digest(expected, received):
        raise KeyConfirmationError("key confirmation mac did not verify")
