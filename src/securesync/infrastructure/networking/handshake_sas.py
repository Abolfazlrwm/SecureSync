"""Short authentication string (SAS) derivation for pairing (1f).

The SAS is the value two users compare out of band to rule out an active
man-in-the-middle during first contact. It is derived from the *final*
transcript, so it covers both Ed25519 identities, both ephemeral keys, both
nonces, both signatures and both confirmation MACs
(``docs/design/1e-handshake.md`` §7.1):

```text
sas_material = H(T1 ‖ b"-sas" ‖ t_final)
```

Rendering (design §7.2):

* **Default: four words** from the 2048-entry list in
  :mod:`~securesync.infrastructure.networking.sas_wordlist`, 11 bits each, so
  44 bits of the material are shown.
* **Explicit alternative: eight decimal digits** (26.6 bits), for users who
  would rather read numbers aloud.

Why four words and not eight digits by default: a short SAS can be *ground*.
An active man-in-the-middle can vary its own ephemeral key and nonce offline,
towards one side only, until the SAS that side computes matches the value it
showed the other side. The only thing bounding that search is the handshake
deadline, so 26.6 bits is too small to rely on; 44 bits raises the cost by
roughly 2^17.4. The proper fix is commit-then-reveal (ZRTP-style), recorded for
evaluation in 1f — it removes the offline grind instead of pricing it.

This module deliberately does **not** implement attempt limiting, pinning or
CLI behaviour; those belong to 1f. It only derives and renders.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Final

from securesync.core.protocol import ProtocolError
from securesync.infrastructure.networking.handshake_keys import TRANSCRIPT_SIZE
from securesync.infrastructure.networking.handshake_messages import T1
from securesync.infrastructure.networking.sas_wordlist import SAS_WORDS

#: Number of words in the SAS wordlist. Fixed at 2048 so one word is 11 bits.
WORDLIST_SIZE: Final = 2048
#: Bits contributed by each word (``log2(2048)``).
BITS_PER_WORD: Final = 11
#: Default number of words shown to the user (44 bits).
DEFAULT_WORD_COUNT: Final = 4
#: Maximum number of words this module will render (88 bits, well under 256).
MAX_WORD_COUNT: Final = 8
#: Number of decimal digits in the alternative rendering.
DIGIT_COUNT: Final = 8
#: Maximum number of digits this module will render.
MAX_DIGIT_COUNT: Final = 12

_SAS_LABEL: Final = b"-sas"


class SasError(ProtocolError):
    """Raised when a SAS cannot be derived or rendered."""


def sas_material(transcript_final: bytes) -> bytes:
    """Derive the 32-byte SAS material from the final transcript hash.

    Args:
        transcript_final: ``t_final`` from the v3 handshake.

    Returns:
        ``H(T1 ‖ b"-sas" ‖ t_final)``.

    Raises:
        SasError: If ``transcript_final`` is not a SHA-256 digest.
    """
    if len(transcript_final) != TRANSCRIPT_SIZE:
        raise SasError(f"t_final must be {TRANSCRIPT_SIZE} bytes, got {len(transcript_final)}")
    return hashlib.sha256(T1 + _SAS_LABEL + transcript_final).digest()


def entropy_bits(count: int) -> int:
    """Return how many bits of the material ``count`` words actually show.

    Args:
        count: Number of words.

    Returns:
        ``count * 11``.

    Raises:
        SasError: If ``count`` is outside ``1..MAX_WORD_COUNT``.
    """
    _check_word_count(count)
    return count * BITS_PER_WORD


def _check_word_count(count: int) -> None:
    if not 1 <= count <= MAX_WORD_COUNT:
        raise SasError(f"word count must be 1..{MAX_WORD_COUNT}, got {count}")


def sas_words(
    material: bytes,
    *,
    count: int = DEFAULT_WORD_COUNT,
    wordlist: Sequence[str] = SAS_WORDS,
) -> tuple[str, ...]:
    """Render ``count`` words by taking the leading bits of ``material``.

    Bits are consumed most-significant first, so the first word depends only on
    the first 11 bits of the digest. The mapping is pure and deterministic:
    both peers derive the identical tuple from identical material.

    Args:
        material: The output of :func:`sas_material`.
        count: How many words to render (1..:data:`MAX_WORD_COUNT`).
        wordlist: The word table; must have :data:`WORDLIST_SIZE` entries.

    Returns:
        The words, in display order.

    Raises:
        SasError: If ``material`` is too short for ``count``, or ``count`` or
            ``wordlist`` is invalid.
    """
    _check_word_count(count)
    if len(wordlist) != WORDLIST_SIZE:
        raise SasError(f"wordlist must have {WORDLIST_SIZE} entries, got {len(wordlist)}")
    needed_bits = count * BITS_PER_WORD
    if len(material) * 8 < needed_bits:
        raise SasError(
            f"material has {len(material) * 8} bits, {needed_bits} needed for {count} words"
        )

    value = int.from_bytes(material, "big")
    total_bits = len(material) * 8
    mask = WORDLIST_SIZE - 1
    return tuple(
        wordlist[(value >> (total_bits - BITS_PER_WORD * (index + 1))) & mask]
        for index in range(count)
    )


def sas_digits(
    material: bytes,
    *,
    count: int = DIGIT_COUNT,
) -> str:
    """Render ``count`` decimal digits as a zero-padded string.

    The whole material is reduced modulo ``10 ** count``. The modulo bias is
    negligible — ``2**256`` is not a multiple of ``10**8``, but the deviation
    is on the order of ``10**-69`` — so it is not worth a rejection loop.

    Args:
        material: The output of :func:`sas_material`.
        count: How many digits to render (1..:data:`MAX_DIGIT_COUNT`).

    Returns:
        Exactly ``count`` ASCII digits.

    Raises:
        SasError: If ``count`` is out of range or ``material`` is empty.
    """
    if not 1 <= count <= MAX_DIGIT_COUNT:
        raise SasError(f"digit count must be 1..{MAX_DIGIT_COUNT}, got {count}")
    if not material:
        raise SasError("material must not be empty")
    return str(int.from_bytes(material, "big") % 10**count).zfill(count)


def format_sas(words: Sequence[str], *, separator: str = "-") -> str:
    """Join rendered words for display or for the user to read back.

    Args:
        words: The output of :func:`sas_words`.
        separator: Placed between words.

    Returns:
        The joined string, e.g. ``"correct-horse-battery-staple"``.

    Raises:
        SasError: If ``words`` is empty.
    """
    if not words:
        raise SasError("at least one word is required")
    return separator.join(words)
