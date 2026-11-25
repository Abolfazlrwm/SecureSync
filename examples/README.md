# Examples

## Two-peer local demo (`config/peer-a.yaml`, `config/peer-b.yaml`)

Sample configuration for the two-container setup in the repository root's
`docker-compose.yml` (see [docs/deployment.md](../docs/deployment.md)).
Peer A syncs whatever is placed in its `data/` directory to peer B, over
the encrypted transfer path, using the same schema `YamlConfigLoader`
parses.

```bash
# from the repository root
docker compose up --build
```

Then drop a file into `examples/data/peer-a/` and watch it appear in
`examples/data/peer-b/`. Peers find each other through mDNS, which needs
multicast to work between the containers; on platforms where Docker
bridge networks do not pass multicast, discovery may need a little help
(run both containers with `--network host` as a fallback).

## `data/peer-a/`, `data/peer-b/`

Empty, gitignored-content directories mounted into each container as the
synced folder. Kept in git only via `.gitkeep` so the directory
structure is present on clone.
