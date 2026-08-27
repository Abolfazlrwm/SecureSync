"""Domain port for exchanging chunk manifests with a peer over the network.

Sits alongside :class:`~securesync.domain.transfer.TransferTransport`:
that port only *pushes* chunk bytes (`send_chunk`) — its
`request_chunks` never actually asks the peer for anything, it just
waits for whatever the peer already decided to push (see
``docs/adr/0017-tcp-transfer-transport.md``'s and
``0018-key-exchange-handshake.md``'s disclosed "no real
request/response round trip" limitation). `ManifestExchangeTransport`
is where a real pull lives: `request_manifest` asks what a peer has
for a file; `request_chunks` asks for specific chunks' actual bytes.
See ``docs/adr/0022-file-synchronization-use-case.md``.

Phase 17: `request_manifest` now returns a `ManifestWithVersion` —
the chunk collection paired with the `VersionVector` the peer
recorded for that file's causal history — so callers can decide
which direction to sync (push, pull, conflict, noop) without
re-fetching metadata from a second port. See
``docs/adr/0024-version-aware-sync-direction.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass

from securesync.domain.chunk import Chunk, ChunkCollection
from securesync.domain.conflict import VersionVector
from securesync.domain.networking import Peer


@dataclass(frozen=True, slots=True)
class ManifestWithVersion:
    """A peer's manifest paired with the VersionVector that describes its lineage.

    Attributes:
        collection: The ChunkCollection the peer holds for this file.
        version: The VersionVector the peer recorded for this file's
            causal history. ``None`` means the peer has the file but
            no recorded version (a peer that doesn't use SyncOrchestrator
            or that pre-dates Phase 7).
    """

    collection: ChunkCollection
    version: VersionVector | None


class ManifestExchangeTransport(ABC):
    """Requests a peer's chunk manifest, and specific chunks' bytes, for a file."""

    @abstractmethod
    async def request_manifest(self, peer: Peer, relative_path: str) -> ManifestWithVersion | None:
        """Request `peer`'s manifest for `relative_path`.

        Args:
            peer: The peer to request the manifest from.
            relative_path: The file to request a manifest for, as a
                path relative to each side's own sync root. Never an
                absolute path — the two peers' sync directories
                generally live at different absolute locations, so an
                absolute path can't be a shared identifier between them.

        Returns:
            The peer's manifest + version vector for that file, or
            `None` if the peer doesn't have (or doesn't recognize) that file.

        Raises:
            OSError: If the peer can't be reached.
        """
        raise NotImplementedError

    @abstractmethod
    def request_chunks(
        self, peer: Peer, relative_path: str, chunk_hashes: list[str]
    ) -> AsyncIterator[Chunk]:
        """Request specific chunks' bytes for `relative_path` from `peer`, by hash.

        Unlike :meth:`~securesync.domain.transfer.TransferTransport.request_chunks`,
        this is a real pull: the peer is actively asked for exactly
        these chunks and reads them from its own copy of the file to
        answer, rather than the caller waiting for whatever the peer
        happens to have already pushed.

        Args:
            peer: The peer to request chunks from.
            relative_path: The file the requested chunks belong to,
                as a path relative to each side's own sync root.
            chunk_hashes: The hex digests of the chunks to request.

        Yields:
            Each requested chunk that the peer actually has, with its
            real data. A hash the peer doesn't have is silently
            omitted rather than erroring the whole request.

        Raises:
            OSError: If the peer can't be reached.
        """
        raise NotImplementedError
