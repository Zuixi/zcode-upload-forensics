---
name: zcode-upload-forensics
description: Forensically determine whether the ZCode desktop client (Zhipu / Z.ai) silently packed and uploaded this machine's workspaces — including full Git history — to a vendor object store, and produce a single-file HTML evidence report. Use when the user asks "did ZCode upload my code", "check if ZCode uploaded my repo", "audit ZCode snapshot upload", "my git history was leaked", "block ZCode from uploading", or in Chinese "zcode 是否上传了我的代码"、"排查 zcode 静默上传 / 快照上传"、"我的 git 历史被传走了吗"、"给 zcode 加锁". Read-only against local files, no network, no decryption, never reads workspace file contents; locking is opt-in and reversible.
license: MIT
compatibility: Python 3.9+ (standard library only, no third-party packages). macOS, Linux and Windows. Read-only by default; the optional lock step requires an OS-specific permission change and is off unless explicitly requested.
metadata:
  version: 0.1.0
  homepage: https://github.com/Zuixi/zcode-upload-forensics
  repository: https://github.com/Zuixi/zcode-upload-forensics
---

# ZCode Upload Forensics

Translate "a pile of local state files plus a minified client bundle" into a **reproducible, falsifiable, confidence-rated verdict** about whether workspace snapshots were uploaded — then render a self-contained HTML report.

## Boundaries (read first)

- Read-only against local files. **No network, no decryption, no deletion of evidence, no reading of workspace file contents.**
- The report contains repository paths, branch names and internal host names. Write it locally, tell the user not to commit or forward it, and use `--redact` when it must be shared.
- `--apply-lock` changes system state (ACL / immutable flag): **off by default**, requires explicit confirmation, and is fully reversible.

## Workflow

1. **Collect, decide, render** (read-only):

   ```bash
   python3 scripts/diagnose.py --out ./zcode-upload-report.html
   ```

   Useful flags: `--list-paths` (print the path-detection ledger **before** doing anything else), `--lang {auto,en,zh}` (report language; `auto` follows the system locale, so a Chinese system gets a Chinese report and everything else gets English), `--redact` (mask paths, branch names, remote hosts), `--no-scan` (skip the ~300 MB bundle scan: instant, but the code semantics stay unverified), `--diff prev.json` (what changed since the previous run), `--install-dir/--zcode-dir/--home/--platform` (override detection; `--platform` is for cross-inspection and **blocks** lock operations).

2. **Read the result.** The CLI prints the verdict plus the HTML/JSON paths. Report sections are fixed: conclusion and reasoning → matched truth-table row → workspace evidence → path-detection ledger → client code signatures → auxiliary traces → timeline → remediation → open questions → reproduction commands.

3. **When summarizing for the user, always include**: the verdict in one sentence, the scope of what was taken (`.git/objects` size and share, branch and worktree counts, sensitive-pattern hits), the `falsifiers` (what would overturn the conclusion), and the fact that **anything already uploaded cannot be recalled**.

4. **To block further uploads**, read `references/platform-locks.md` first, then explain the impact and get confirmation before running:

   ```bash
   python3 scripts/diagnose.py --verify-lock    # is it already locked?
   python3 scripts/diagnose.py --apply-lock     # quarantine evidence + lock + write-probe verify
   python3 scripts/diagnose.py --unlock         # reversible
   ```

5. **After changing the scripts, always re-run the regression**: `python3 scripts/selftest.py` (18 synthetic fixtures covering every verdict branch, signature drift, `--no-scan`, `--redact`, `--diff`, both report languages, stdlib-only, simulated macOS/Linux layouts, environment-variable overrides, the detection ledger, the lock guard and a host-bundle-only machine). Add `--with-lock` to also exercise the real OS lock primitives against a throwaway fixture. It never touches a real `~/.zcode`.

Machine-readable signals for automation live in `verdict.flags` (e.g. `accepted_records`, `evidence_wiped`, `signature_drift`) — assert on those rather than on rendered prose, which is localised.

## Verdict truth table

| Pipeline present | `accepted` hash | pending ciphertext | manifest | verdict |
|---|---|---|---|---|
| no | – | – | – | `FEATURE_ABSENT` |
| yes | – | – | – | `NO_LOCAL_TRACE` |
| yes | – | – | yes | `CAPTURED_NOT_ACCEPTED` |
| yes | – | yes | yes | `PACKED_PENDING` |
| yes | yes | – | yes | **`UPLOADED`** |
| yes | evidence wiped | ? | ? | `INCONCLUSIVE` |

Field semantics, code-path carriers and the four interpretation rules live in `references/evidence-map.md` (it explains why `lastAcceptedManifestHash` is equivalent to "the OSS upload succeeded").

## Hard rules (violating any of these produces a false report)

1. **An empty `pending/` does not mean safe.** Empty pending *without* an accepted hash is `INCONCLUSIVE` — never report "not uploaded / safe".
2. **A manifest is not an upload.** A manifest alone proves nothing.
3. **Local physical evidence outranks the code interpreter.** If signature scanning fails (version drift, non-standard install) but an accepted record exists locally, the verdict stays `UPLOADED` with downgraded confidence plus a warning — never fall back to "safe".
4. **Never read "empty directory" as "never used".** On this machine the `checkpoints` directory was observed being deleted and recreated empty shortly after the client exited. An empty directory must be cross-checked against `repoSnapshotIndexingUserConfigured` in `setting.json`, the Electron userData directory, and `git-checkpoint` traces in the logs.
5. **Remote workspaces do not count.** Workspaces with a non-empty `workspaceIdentity` (SSH/remote) do not produce a local snapshot; do not include them in the impact scope.
6. **All numbers come from the script.** Sizes, counts and hit totals must be taken from the `--json` output — never recomputed from grep output.
7. **A ciphertext far smaller than the manifest implies an earlier full baseline.** `.git/objects` is already zlib-compressed, so gzip barely shrinks it; a ratio far below 1 means the last artifact was an incremental delta, which means a full workspace upload happened earlier. Never console the user with "it was only 444 KB".

## Portability (no hardcoded paths)

Never assume the current machine. Everything is probed and written into the report so it can be audited:

| Target | Probe order (first match wins) |
|---|---|
| Home directory | `--home` → `%USERPROFILE%` (Windows) / `$HOME` (POSIX) → `expanduser` |
| Data root | `--zcode-dir` → `ZCODE_DATA_BASE_DIR`/`ZCODE_DATA_DIR`/`ZCODE_HOME` → `<home>/.zcode` → under WSL, `/mnt/c/Users/*/.zcode` |
| Install dir | `--install-dir` → `ZCODE_INSTALL_DIR`/`ZCODE_APP_PATH` → `PATH` lookup → Windows registry (HKLM/HKCU × 32/64-bit: `InstallLocation`/`DisplayIcon`/`UninstallString`) → per-drive `Program Files`/`LocalAppData` → macOS `.app` bundle → Linux `/opt`·`/usr/*`·`~/.local`·snap → `server/`·`computer-use/` bundles inside the data dir → **the running process's executable path** (the only fallback that works for AppImage or a renamed bundle) |
| Client payload | `resources/app.asar` · `app.asar` · `app/` directory · **`server/zcode-server.cjs` (remote-host bundle)**; candidates are scanned in priority order and the scan stops on the first confirmed match, reporting **which one was actually used** |
| Electron userData | `%APPDATA%`/`%LOCALAPPDATA%` (Win) · `~/Library/Application Support` (macOS) · `~/.config` (Linux), validated by Chromium profile markers (`.updaterId`, `session/Local Storage`) |
| Lock principal | Windows `whoami` → `%USERDOMAIN%\%USERNAME%` → `%USERNAME%`, with automatic retry using the bare user name when `icacls` rejects the domain form |

Platform is detected with `platform.system()` (`--platform` overrides it for cross-inspection only); lock commands branch on the **real** platform, never on the override.

Section "path detection ledger" in the report lists every detected path, **how it was found**, and the full candidate list, so a wrong guess is visible immediately.

**Explicit flags are authoritative**: once `--install-dir` / `--zcode-dir` is given, no fallback probing happens — otherwise the tool would silently answer a different question than the one asked. Fallback only applies to automatic detection.

**Runtime**: Python **3.9+** (the system `python3` on macOS is enough; zero third-party dependencies). A version guard runs at entry.

## Repository layout

```
scripts/diagnose.py            CLI entry point (thin; logic lives in the package)
scripts/zcode_forensics/       one concern per module
  constants.py                 signature needles, schemas, static tables
  messages.py                  localisation catalogue + detect_lang/tr
  util.py                      formatting, IO, error collection
  detection.py                 path, install and payload discovery
  signatures.py                bundle signature scan + invariant check
  collect.py                   evidence collection from the data directory
  verdict.py                   truth table decision + machine-readable flags
  report.py                    HTML rendering
  locking.py                   verify / quarantine+lock / restore
  diffing.py                   comparison against a previous report
  cli.py                       argument parsing and wiring
scripts/selftest.py            regression suite (synthetic fixtures only)
```

Keep the whole `scripts/` tree together when copying this skill: `diagnose.py` imports its sibling package and will fail with a clear error if the package is missing.

## Reference files

- `references/evidence-map.md` — `state.json` field semantics, client code carriers and the `accepted == uploaded` invariant, the v2 manifest schema, interpretation rules, and evidence volatility. Read it when explaining a field or doing a manual cross-check.
- `references/platform-locks.md` — lock/verify/restore commands for Windows, macOS and Linux, the quarantine policy, degraded options, and how to handle data that has already been uploaded. **Required reading before running a lock.**
