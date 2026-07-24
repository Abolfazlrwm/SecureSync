# Troubleshooting

> Status: **Living document** — this page grows as real issues surface
> during development and from user reports; no runtime behavior exists yet
> to troubleshoot (Phase 0/0.5). It exists now (with a fixed structure) so
> every future troubleshooting entry is added consistently instead of ad hoc.

## How to file an entry here

Each entry follows this shape:

```markdown
### Symptom: <what the user observes>

**Likely cause:** <root cause>

**Fix / workaround:** <steps>

**Diagnostics:** <what logs/commands confirm this diagnosis>
```

## Where to look first

| Question | Where to check |
|---|---|
| Is the process running? | `docker ps` / `systemctl status securesync` (see `docs/deployment.md`) |
| Are two devices seeing each other at all? | Discovery logs — `logging.level: debug` (see `docs/configuration.md`) |
| Is a specific file not syncing? | Check `sync.folders.ignore` patterns in `config.yaml`; check the SQLite metadata store for that file's tracked state |
| Is a peer connection failing authentication? | Check the device fingerprint shown locally matches what was authorized — see `docs/security.md` §3 |
| Is sync slow? | Compare against `docs/performance.md` targets; check `logging.level: debug` for chunk-level timing |

## Known issues

*(None yet — this is a Phase 0 scaffold. Populated starting with the first
real implementation phase.)*

## Getting more help

- Search [existing issues](https://github.com/<org>/securesync/issues)
- Open a new issue using the Bug report template
  (`.github/ISSUE_TEMPLATE/bug_report.yml`)
- For security-related problems, see [SECURITY.md](../SECURITY.md) instead
  of opening a public issue
