"""Domain port for exchanging chunk manifests with a peer over the network.

Sits alongside :class:`~securesync.domain.transfer.TransferTransport`:
that port moves chunk *bytes* once you already know which ones you
need; `ManifestExchangeTransport` is how you find that out in the
first place — asking a peer for its
:class:`~securesync.domain.chunk.ChunkCollection` for a given file so
:class:`~securesync.domain.delta.DeltaCalculator` has something to
diff the local manifest against. See
``docs/adr/0021-manifest-exchange-protocol.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from securesync.domain.chunk import ChunkCollection
from securesync.domain.networking import Peer


class ManifestExchangeTransport(ABC):
    """Requests a peer's chunk manifest for a specific file."""

    @abstractmethod
    async def request_manifest(self, peer: Peer, source_path: str) -> ChunkCollection | None:
        """Request `peer`'s manifest for `source_path`.

        Args:
            peer: The peer to request the manifest from.
            source_path: The file path to request a manifest for, as
                the peer identifies it locally.

        Returns:
            The peer's `ChunkCollection` for that file, or `None` if
            the peer doesn't have (or doesn't recognize) that file.

        Raises:
            OSError: If the peer can't be reached.
        """
        raise NotImplementedError
