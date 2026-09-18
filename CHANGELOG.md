# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Decoupled the collector into a package.** `scripts/diagnose.py` is now a thin entry point; the logic lives in `scripts/zcode_forensics/` (constants, messages, util, detection, signatures, collect, verdict, report, locking, diffing, cli). Module imports are explicit and acyclic — nothing wildcard-imports.

### Added

- [`docs/findings.md`](./docs/findings.md): what was measured, on which client builds, how, and what remains unverified — including the two-machine comparison and the host-bundle-only case.
- `verdict.flags`: locale-independent machine-readable signals (`accepted_records`, `evidence_wiped`, `signature_drift`, …) so tests and automation never match rendered prose.
- Bilingual English/Chinese documentation (`README.md`, `README.zh.md`).
- English as the primary report language, with `--lang {auto,en,zh}` and locale auto-detection.
- CI matrix: Linux/macOS/Windows × Python 3.9/3.12/3.13, plus a real lock/unlock job per platform.

## [0.1.0] - 2026-09-19

Initial release.

### Added

- **Verdict engine** with six outcomes (`UPLOADED`, `PACKED_PENDING`, `CAPTURED_NOT_ACCEPTED`, `INCONCLUSIVE`, `NO_LOCAL_TRACE`, `FEATURE_ABSENT`), each carrying confidence and explicit falsifiers.
- **Client code signature scan** that verifies the `markAcceptedManifest` ⇄ `uploadObject` adjacency invariant, so "accepted" can be read as "the OSS upload returned 2xx" — and downgrades confidence instead of guessing when the invariant cannot be confirmed.
- **Payload carrier detection**: `resources/app.asar`, unpacked `app/`, macOS `.app` bundles, and the remote-host bundle `~/.zcode/server/zcode-server.cjs`, tried in priority order with the accepted carrier reported.
- **Path detection with an audit trail**: home, data root, install dir, Electron userData and lock principal are all probed (flags, env vars, Windows registry, `PATH`, platform-standard locations, running-process executable), and the report lists every path, how it was found, and the full candidate list.
- **Single-file HTML report**: verdict, matched truth-table row, per-workspace evidence (`.git/objects` share, branches, worktrees, sensitive-path hits, shipped global configs), detection ledger, signature scan, auxiliary traces, timeline, remediation, open questions and reproduction commands.
- **Impact analysis**, including the heuristic that a ciphertext far smaller than the manifest implies an earlier full baseline upload.
- **Optional, reversible lock**: quarantine the evidence directory, deny writes (`icacls` / `chflags` / `chattr`), verify with a write probe, and restore with `--unlock`.
- **Redaction mode** (`--redact`) that hashes branch names, worktree names and remote hosts.
- **18 synthetic fixture cases** covering every verdict branch, signature drift, `--no-scan`, `--redact`, `--diff`, both report languages (asserting the English report contains no CJK), a standard-library-only check, simulated macOS/Linux layouts, environment-variable overrides, the detection ledger, the lock guard, a host-bundle-only machine, and an opt-in `--with-lock` mode that exercises the real OS lock primitives.

### Verified against

- ZCode **3.11.2** on Windows (desktop bundle, registry-discovered non-default install drive).
- ZCode **3.7.7** on macOS 26.2 (`.app` bundle and remote-host bundle), Python 3.9.6.

[Unreleased]: https://github.com/Zuixi/zcode-upload-forensics/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Zuixi/zcode-upload-forensics/releases/tag/v0.1.0
