# Examples

## Two-peer local demo (`config/peer-a.yaml`, `config/peer-b.yaml`)

Sample configuration for the two-container setup in the repository root's
`docker-compose.yml` (see [docs/deployment.md](../docs/deployment.md)).
Each peer syncs whatever is placed in its `data/` directory.

```bash
# from the repository root
docker compose up --build
```

Then drop a file into `examples/data/peer-a/` and, once Phase 1–6 are
implemented, watch it appear in `examples/data/peer-b/`.

**Status:** the config files and compose topology are ready now (Phase
0.5). Phase 1 (Filesystem Watcher) and Phase 2 (Chunk Engine) are
implemented, but neither is wired into a runnable CLI yet (that's Phase
9), and nothing crosses the network without Phase 4 (Peer Discovery) and
Phase 5 (Transfer Engine) — so dropping a file into `peer-a/` still has
nothing to sync it to `peer-b/` yet.

## `data/peer-a/`, `data/peer-b/`

Empty, gitignored-content directories mounted into each container as the
watched sync folder. Kept in git only via `.gitkeep` so the directory
structure is present on clone.
