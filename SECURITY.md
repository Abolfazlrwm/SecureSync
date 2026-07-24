# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately using one of:

- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
  feature on this repository ("Security" tab → "Report a vulnerability").
- Email: `security@<project-domain>` *(placeholder — set once the project
  has a domain / dedicated address)*.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal reproduction is very helpful)
- The affected version/commit
- Whether the issue is already public

## What to expect

- **Acknowledgement** within 72 hours.
- We will work with you to understand and validate the issue, and agree on
  a disclosure timeline before any public announcement.
- Credit is given to reporters in the release notes, unless anonymity is
  requested.

## Supported Versions

*(Placeholder — populated once the first tagged release exists. Until then,
only the `main` branch is supported.)*

| Version | Supported |
|---|---|
| `main` | ✅ |

## Threat Model Summary

The full threat model lives in [docs/security.md](docs/security.md). In
summary, SecureSync's design must resist:

| Threat | Primary mitigation |
|---|---|
| Replay attack | Per-session nonces, monotonic message counters, authenticated encryption |
| Man-in-the-middle | X25519 key exchange, mutual peer authentication, device fingerprint verification |
| Packet injection / tampering | AEAD (AES-256-GCM / ChaCha20-Poly1305) authenticates every packet |
| Spoofing | Peer authentication before any data exchange; no unauthenticated peer is trusted |
| Denial of service | Rate limiting, connection backoff, bounded resource allocation per peer |
| Unauthorized peers | Explicit device pairing/authorization step before sync begins |

SecureSync **never implements custom cryptographic primitives**. All
cryptography is composed from the audited [`cryptography`](https://cryptography.io/)
(pyca) library. If you believe a specific composition of these primitives is
unsafe, that is exactly the kind of report we want — please report it
privately as above.
