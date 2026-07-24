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
0.5); they have nothing to actually sync yet since no implementation code
exists before Phase 1.

## `data/peer-a/`, `data/peer-b/`

Empty, gitignored-content directories mounted into each container as the
watched sync folder. Kept in git only via `.gitkeep` so the directory
structure is present on clone.
