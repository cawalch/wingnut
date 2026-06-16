# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in wingnut, please report it
**privately** rather than opening a public issue.

- **Email:** cawalch@pm.me
- Please include a description of the issue, steps to reproduce, and the
  impact. A proof-of-concept is appreciated but not required.

We aim to acknowledge reports within **72 hours** and to ship or disclose
a fix within **30 days** for high-severity issues. Please do not publicly
disclose the vulnerability before a fix is released.

## Supported Versions

Only the latest released version receives security updates.

| Version | Supported |
|---------|-----------|
| latest (0.5.x) | ✅ |
| older          | ❌ |

## Supply-Chain Posture

This project publishes results to the OpenSSF Scorecard. The current
posture and per-check breakdown are visible at:
https://scorecard.dev/viewer/?uri=github.com/cawalch/wingnut

Published npm packages ship with build provenance and SBOM attestations
under trusted publishing (OIDC); verify with:

```sh
gh attestation verify <package>.tgz --repo cawalch/wingnut
```
