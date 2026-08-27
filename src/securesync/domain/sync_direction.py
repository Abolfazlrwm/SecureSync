"""Domain service for deciding the sync direction of one file with one peer.

`SyncDirectionResolver` compares the local and remote `VersionVector`
for a single file and returns one of four outcomes:

- ``PUSH`` — the local version is strictly newer than the remote;
  push our chunks to the peer.
- ``PULL`` — the remote version is strictly newer than the local;
  pull their chunks down.
- ``CONFLICT`` — the versions are concurrent (neither is an ancestor
  of the other); callers should run a merge strategy (currently
  Phase 7's Last Writer Wins via `LastWriterWinsStrategy`).
- ``NOOP`` — neither side has anything newer than the other (vectors
  are equal, or both empty); no transfer is needed.

A ``None`` remote version (a peer that doesn't record versions, e.g.
a legacy setup or one that pre-dates Phase 7) falls back to the
content-hash comparison that Phase 15/16 already did: if the local
manifest has any chunk the peer's manifest doesn't, PUSH; if the
peer's has any the local doesn't, PULL; else NOOP. CONFLICT can't
be detected without a version, so this fallback never returns it —
matching the pre-Phase-17 behavior that ADR-0023 deferred.

This is a stateless domain service — the comparison is pure on its
two inputs. See ``docs/adr/0024-version-aware-sync-direction.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique

from securesync.domain.chunk import ChunkCollection
from securesync.domain.conflict import VersionVector


@unique
class SyncDirection(StrEnum):
    """The direction a single file's sync should take with a single peer."""

    PUSH = "push"          # Send our newer version to the peer.
    PULL = "pull"          # Fetch the peer's newer version.
    CONFLICT = "conflict"  # Versions are concurrent; defer to merge strategy.
    NOOP = "noop"          # Nothing to transfer; vectors match or both empty.


@dataclass(frozen=True, slots=True)
class SyncDirectionDecision:
    """The result of resolving sync direction for one file with one peer.

    Attributes:
        direction: Which direction (or noop/conflict) to take.
        reason: A short, human-readable explanation suitable for logging.
    """

    direction: SyncDirection
    reason: str


class SyncDirectionResolver:
    """Decides push/pull/conflict/noop for one file with one peer.

    Stateless: same two inputs always produce the same decision.
    """

    def resolve(
        self,
        local_collection: ChunkCollection | None,
        local_version: VersionVector | None,
        remote_collection: ChunkCollection | None,
        remote_version: VersionVector | None,
    ) -> SyncDirectionDecision:
        """Compare local vs remote state and return the sync direction.

        Args:
            local_collection: The locally-known chunk manifest, or
                ``None`` if this file doesn't exist locally.
            local_version: The local file's causal version vector,
                or ``None`` if unknown (e.g. before Phase 7 metadata).
            remote_collection: The peer's chunk manifest, or ``None``
                if the peer doesn't have this file.
            remote_version: The peer's reported version vector, or
                ``None`` if the peer doesn't record versions.

        Returns:
            A `SyncDirectionDecision` describing which direction
            (or NOOP/CONFLICT) to take. Never raises.
        """
        # No peer manifest → nothing to pull, but maybe we still
        # want to push our local copy to a peer that's never seen it.
        if remote_collection is None and remote_version is None:
            if local_collection is not None and local_collection.chunk_count > 0:
                return SyncDirectionDecision(
                    SyncDirection.PUSH,
                    "peer has no manifest for this file; pushing ours",
                )
            return SyncDirectionDecision(
                SyncDirection.NOOP, "neither side has the file"
            )

        # Both version vectors present: this is the fast path.
        if local_version is not None and remote_version is not None:
            return self._resolve_with_versions(
                local_version, remote_version, local_collection, remote_collection
            )

        # Fallback: no versions (or only one side) — diff on chunk hashes.
        return self._resolve_without_versions(local_collection, remote_collection)

    def _resolve_with_versions(
        self,
        local_version: VersionVector,
        remote_version: VersionVector,
        local_collection: ChunkCollection | None,
        remote_collection: ChunkCollection | None,
    ) -> SyncDirectionDecision:
        if local_version < remote_version:
            return SyncDirectionDecision(
                SyncDirection.PULL,
                f"remote version {remote_version.counters} is newer than "
                f"local {local_version.counters}",
            )
        if remote_version < local_version:
            return SyncDirectionDecision(
                SyncDirection.PUSH,
                f"local version {local_version.counters} is newer than "
                f"remote {remote_version.counters}",
            )
        # Versions are equal: fall through to content-hash diff to
        # catch the edge case where two peers independently edited
        # the same logical version (rare but possible if one side
        # rewrote its metadata without incrementing its counter).
        decision = self._diff_content_hashes(local_collection, remote_collection)
        if decision.direction is SyncDirection.CONFLICT:
            # Equal versions but different content is the most
            # dangerous case: the version vector lies about causality.
            # Treat as CONFLICT (Last Writer Wins will pick one) so
            # the caller doesn't silently overwrite.
            return decision
        if decision.direction is SyncDirection.NOOP:
            return SyncDirectionDecision(
                SyncDirection.NOOP,
                f"versions equal ({local_version.counters}) and content matches",
            )
        return decision

    def _resolve_without_versions(
        self,
        local_collection: ChunkCollection | None,
        remote_collection: ChunkCollection | None,
    ) -> SyncDirectionDecision:
        # No version info: use the content-hash-only diff from
        # Phase 15/16. CONFLICT can't be detected without a vector,
        # so a content mismatch just defaults to PUSH (matching the
        # pre-Phase-17 auto-push behavior on newly-discovered peers).
        decision = self._diff_content_hashes(local_collection, remote_collection)
        if decision.direction is SyncDirection.CONFLICT:
            return SyncDirectionDecision(
                SyncDirection.PUSH,
                "no version vectors; falling back to content-hash PUSH",
            )
        return decision

    @staticmethod
    def _diff_content_hashes(
        local_collection: ChunkCollection | None,
        remote_collection: ChunkCollection | None,
    ) -> SyncDirectionDecision:
        """Decide direction based on which side has chunks the other lacks.

        Returns:
            PUSH if local has any chunk hash the remote doesn't
                  (and the reverse isn't true);
            PULL if remote has any chunk hash the local doesn't
                  (and the reverse isn't true);
            CONFLICT if both sides have chunks the other lacks;
            NOOP if both sides have the same set of chunks.
        """
        local_hashes: set[str] = set()
        if local_collection is not None:
            local_hashes = {
                m.chunk_hash.digest
                for m in local_collection.chunks
                if m.chunk_hash is not None
            }
        remote_hashes: set[str] = set()
        if remote_collection is not None:
            remote_hashes = {
                m.chunk_hash.digest
                for m in remote_collection.chunks
                if m.chunk_hash is not None
            }

        local_only = local_hashes - remote_hashes
        remote_only = remote_hashes - local_hashes

        if local_only and remote_only:
            return SyncDirectionDecision(
                SyncDirection.CONFLICT,
                "both sides have chunks the other lacks",
            )
        if local_only:
            return SyncDirectionDecision(
                SyncDirection.PUSH, "local has chunks remote doesn't"
            )
        if remote_only:
            return SyncDirectionDecision(
                SyncDirection.PULL, "remote has chunks local doesn't"
            )
        return SyncDirectionDecision(SyncDirection.NOOP, "chunk sets are equal")
