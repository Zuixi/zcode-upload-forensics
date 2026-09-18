# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Pages publishes the `docs/` directory, so the example report renders instead of showing its source: <https://zuixi.github.io/zcode-upload-forensics/sample-report.html>.

## [0.1.0] - 2026-09-19

First release.

### Added

- **Verdict engine** with six outcomes (`UPLOADED`, `PACKED_PENDING`, `CAPTURED_NOT_ACCEPTED`, `INCONCLUSIVE`, `NO_LOCAL_TRACE`, `FEATURE_ABSENT`), each carrying a confidence level, explicit reasoning and falsifiers — the conditions that would overturn the conclusion.
- **Client code signature scan** that verifies the `markAcceptedManifest` ⇄ `uploadObject` adjacency invariant in the installed bundle, so "accepted" can be read as "the object upload returned 2xx". When the invariant cannot be confirmed (a new build moved the code) the verdict keeps its local evidence but drops to medium confidence and says so.
- **Payload carrier detection**: `resources/app.asar`, unpacked `app/`, macOS `.app` bundles and the remote-host bundle `<data-dir>/server/zcode-server.cjs`, tried in priority order, with the accepted carrier reported. A machine that never installed the desktop client can still carry the pipeline.
- **Path detection with an audit trail**: home, data root, install directory, Electron userData and the lock principal are all probed (flags → environment variables → Windows registry → `PATH` → platform-standard locations → the running process's executable). The report lists every detected path, *how* it was found, and the full candidate list. Explicit flags are authoritative and never fall back to another location.
- **Single-file HTML report** (one self-contained file, no JavaScript, light and dark theme): hero card with the verdict, confidence and active flags; one card per section; per-workspace statistics; `.git/objects` share, branches, worktrees, sensitive-pattern hits and the global configuration shipped alongside the snapshot; evidence timeline; remediation bound to the detected paths; open questions and reproduction commands. See [`docs/sample-report.html`](./docs/sample-report.html).
- **Impact analysis**, including the heuristic that a ciphertext far smaller than its manifest implies an earlier full-baseline upload (`.git/objects` is already compressed, so gzip should barely shrink it).
- **Optional, reversible lock**: quarantine the evidence directory (never delete it), deny writes with `icacls` / `chflags` / `chattr`, verify the result with a write probe, and restore with `--unlock`. The tool reports `NOT blocked` rather than claiming success when the probe still succeeds.
- **Redaction** with granularity: `--redact` / `--redact all` masks machine paths, branch names, worktree names and remote hosts; `--redact paths` hides home/temp/host while keeping branch names readable; `--redact names` does the reverse.
- **Locale-aware report**: `--lang {auto,en,zh}`; `auto` follows `LC_ALL`/`LANG`, the Windows UI language, then `locale`, and falls back to English.
- **`verdict.flags`**: locale-independent machine-readable signals (`accepted_records`, `pending_artifacts`, `evidence_wiped`, `signature_drift`, …) so tests and automation never match rendered prose.
- [`docs/findings.md`](./docs/findings.md): what was measured, on which client builds, how, and what remains unverified.
- [`docs/sample-report.html`](./docs/sample-report.html) with `scripts/make-sample-report.py`: a committed example rendered from a fully synthetic fixture, regenerable and deterministic.
- Bilingual documentation: [`README.md`](./README.md) and [`README.zh.md`](./README.zh.md).
- **21 synthetic fixture cases** (59 assertions) covering every verdict branch, signature drift, `--no-scan`, `--redact` (all three granularities), `--diff`, both report languages (asserting the English report contains no CJK), standard-library-only, message-catalogue integrity, simulated macOS/Linux layouts, environment-variable overrides, the detection ledger, the lock guard, a host-bundle-only machine, and an opt-in `--with-lock` mode that exercises the real OS lock primitives.
- **CI**: Linux/macOS/Windows × Python 3.9/3.12/3.13, plus a real lock/verify/unlock job on each platform.

### Changed

- **The collector is a package, not one file.** `scripts/diagnose.py` is a thin entry point; the logic lives in `scripts/zcode_forensics/` (constants, messages, util, detection, signatures, collect, verdict, report, locking, diffing, cli). Imports are explicit and acyclic.
- **Message tables hold text only.** All block markup lives in the renderer, so the design can change without touching either translation.
- Workspace cards are ordered by significance (accepted upload → pending artifact → capture only) instead of by directory name.

### Fixed

- **The Windows lock was ineffective on administrator accounts.** An allow-only ACL cannot stop a process whose token carries an `Administrators` allow ACE, which is the default on Windows. The lock now adds an explicit `/deny` ACE for the user's own SID, which outranks every allow. Found by the `real lock (windows-latest)` CI job; every local test on a non-admin account had passed.
- **`--redact` did not mask machine paths.** It covered branch and repository identifiers only, so the detection ledger, the candidate list and the reproduction commands still carried the real home directory. Masking now runs as the last step of document assembly and replaces the longest prefix first.
- The `--platform` guard test picked `linux` unconditionally, so on Linux hosts the override matched the real platform and the guard correctly did not fire. The test now picks a platform that differs from the host.

### Verified against

- ZCode **3.11.2** on Windows (desktop bundle; registry-discovered non-default install drive).
- ZCode **3.7.7** on macOS 26.2 (`.app` bundle and remote-host bundle), Python 3.9.6.
- On both machines the ledger recorded an accepted (uploaded) snapshot, and on the macOS machine `repoSnapshotIndexingEnabled` was `false` — the UI switch is not a mitigation.

[Unreleased]: https://github.com/Zuixi/zcode-upload-forensics/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Zuixi/zcode-upload-forensics/releases/tag/v0.1.0
