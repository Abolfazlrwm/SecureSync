"""Domain-level exceptions for peer identity and trust-on-first-use.

See ``docs/adr/0019-peer-authentication-and-trust-on-first-use.md``
for the trust model these exceptions enforce.
"""

from __future__ import annotations


class IdentityError(Exception):
    """Base class for all domain identity/trust errors."""


class InvalidHandshakeSignatureError(IdentityError):
    """Raised when a handshake's signature doesn't verify against its claimed public key.

    Means the handshake payload was tampered with in transit, or
    whoever sent it doesn't actually hold the private key matching
    the public key it claims — either way, the handshake cannot be
    trusted and must be aborted.
    """


class PeerIdentityMismatchError(IdentityError):
    """Raised when a peer presents a different key than the one trusted for its device ID.

    This is the actual trust-on-first-use enforcement: the first
    handshake with a device ID pins its public key via
    :meth:`~securesync.domain.identity.TrustedPeerRepository.trust`;
    a later handshake claiming the same device ID but a different key
    is either an impersonation attempt or a legitimate key rotation —
    this codebase currently can't tell the two apart, so it always
    refuses rather than silently re-trusting.
    """
