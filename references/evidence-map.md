# Evidence map: the ZCode workspace-snapshot upload pipeline

Reference layer for `SKILL.md`. Read it when you need to explain a field or do a manual cross-check.

`<ZCODE>` is the client data root: `%USERPROFILE%\.zcode` on Windows, `~/.zcode` on macOS/Linux.

## 1. Evidence layout

```
<ZCODE>/v2/checkpoints/<workspaceKeyHash>/
├── state.json                    # the ledger: pack/upload state for this workspace
├── manifests/<hash>.json         # manifest: full list of files that were packed (path + size)
├── extra-manifests/<hash>.json   # global config shipped alongside (second privacy surface)
├── pending/*.enc                 # encrypted artifact not yet uploaded (presence = high risk)
└── tmp/                          # packing scratch space
```

`<workspaceKeyHash>` is a hash of the workspace path; the real path is inside `state.json` as `workspacePath` / `workspaceKey`.

## 2. `state.json` field semantics (these drive the verdict)

| Field | Meaning | Forensic significance |
|---|---|---|
| `workspacePath` / `workspaceKey` | absolute path of the captured workspace | identifies *which* repository was taken |
| `lastCompressedSize.encryptedSizeBytes` | size of the most recent encrypted artifact | against `workspaceSizeBytes` it indicates baseline vs incremental |
| `lastCompressedSize.workspaceSizeBytes` | full workspace size declared by the manifest (**not** the size of this delta) | denominator |
| `lastCompressedSize.manifestHash` | manifest hash of that capture | compare with the accepted hash |
| `lastCompressedSize.recordedAt` | epoch milliseconds | timeline |
| `lastAcceptedManifestHash` / `lastAcceptedManifestPath` | manifest **accepted by the server** | **presence ⇒ at least one OSS upload succeeded** |
| `lastAcceptedExtraManifestHash` | accepted global-config manifest | same |
| `failureCount` | failed retry counter (incremented at turn boundaries) | retry volume |
| `pendingUpload` / `activeUpload` / `latestPendingUpload` | some builds inline the in-flight upload here | equivalent to a non-empty `pending/` |
| `kind` (legacy/inline) | `baseline` = full, `increment` = delta | tells you directly whether the full workspace went up |

## 3. Code-path carriers (`app.asar`)

The pipeline does not live in a single file. Probes cover several carriers (the script enumerates them and falls back from one to the next, reporting which one it accepted):

| Carrier | When it exists |
|---|---|
| `<install>/resources/app.asar` | normal desktop install (Windows/Linux) |
| `<install>/Contents/Resources/app.asar` | macOS `.app` bundle |
| `<install>/resources/app/` (unpacked) | dev / unpacked install |
| `<ZCODE>/server/zcode-server.cjs` | **host bundle pushed by ZCode when the machine is used as a remote workspace host** — a machine with no desktop client can still carry the whole pipeline |
| `<ZCODE>/computer-use/**` | bundled computer-use runtime copy |

Hitting the following strings confirms the build contains the pipeline:

| Signature | Role |
|---|---|
| `/api/v1/snapshot/upload-credential` | requests upload credentials from `zcode.z.ai` (with `workspace_id`) |
| `repo-snapshot.tar.gz.enc` | file name used for the OSS form upload |
| `rsa-oaep-sha256` / `x-oss-security-token` | envelope encryption + direct OSS form upload |
| `captureBeforePrompt` | trigger point (before every prompt) |
| `repo_snapshot_manifest/v2` | manifest schema |

### The invariant this tool relies on

```
GET  /api/v1/snapshot/upload-credential   -> server returns snapshot_id + RSA public key + OSS form signature
local tar -> gzip -> AES-256-CTR -> key wrapped with RSA-OAEP
POST <oss.host>  multipart(file=repo-snapshot.tar.gz.enc)   <- straight to object storage, no vendor API server
OSS callback -> server records the snapshot

flushActiveUpload():
    d = requestUploadTarget(...)        # purely local, uses the cached credential
    if !(await uploadObject(...)).ok -> failPendingUpload(...)   # does NOT write the accepted hash
    markAcceptedManifest(...)           # the only writer of lastAcceptedManifestHash
```

Therefore: **a non-empty `lastAcceptedManifestHash` means `uploadObject` once returned 2xx**.
`markAcceptedManifest` has only two implementations (stateRepo and pendingManager) and exactly one call site, reached only after a successful `uploadObject`. The tool re-checks this heuristically by measuring how close `markAcceptedManifest` and `uploadObject` sit inside the bundle (≤ 8 KB); when they are too far apart, or missing, it **must** downgrade confidence instead of trusting the invariant.

### No switch turns it off

The only gate in `captureBeforePromptUnsafe()` is `tokenProvider()` being able to produce a JWT.
`optimizeAgentExperienceEnabled` (training opt-in only) and `repoSnapshotIndexingEnabled` (server-side indexing only) are **not** on this path.

### Remote workspaces are skipped by the client

`captureBeforePrompt()` returns early when `workspaceIdentity` is non-empty, so SSH/remote workspaces produce no *local* snapshot on the client. Only flag `kind: "local"` entries from `lastWorkspaceSession` to avoid false positives. (A remote *host* machine running the pushed `zcode-server.cjs` is a different story — see section 5b.)

## 4. Interpretation rules (the four that bite)

1. **Empty `pending/` ≠ safe.** Empty pending + accepted hash = uploaded. Empty pending + no accepted hash = unknown.
2. **A manifest ≠ an upload.** Only the accepted fields say anything about transmission.
3. **A ciphertext far smaller than the manifest implies an earlier full baseline.** `.git/objects` is already zlib-compressed, so gzip barely shrinks it and the ratio should be near 1. A ratio ≪ 1 means this artifact was an incremental delta, which means **a full workspace upload happened earlier**. `diagnose.py` emits this hint when `ratio < 0.35` and the manifest exceeds 1 MB (labelled as a heuristic).
4. **`manifests/` modified later than `state.json`** ⇒ a capture happened whose result was never recorded (artifact written then discarded).

## 5. Evidence volatility (observed)

- **Observed on 2026-09-18**: the client exited at 23:10:54 and `<ZCODE>/v2/checkpoints` was deleted and recreated empty at 23:12:54 (creation time equals last-write time, ruling out NTFS timestamp tunnelling). The actor was not proven (client quit-time cleanup, updater or user action all remain possible) — but the conclusion is the same: **the local evidence window is narrow**.
- The upload sidecar **writes no logs**: neither `<ZCODE>/v2/logs` nor `<ZCODE>/cli/log` contains `snapshot/upload-credential` or `repo-snapshot-upload`, so **logs cannot tell you whether an upload happened**.
- Practical consequence: collect while the client is running or right after use, keep the `--json` sidecar, and use `--diff` to monitor changes. When the verdict is `INCONCLUSIVE`, an older JSON is the only way to say what *used to* be there.

## 5b. Cross-machine measurements (2026-09-19)

Measured on macOS 26.2, ZCode **3.7.7**, Python 3.9.6:

- `~/.zcode/v2/checkpoints/f190eadeb03a/state.json` carried `lastAcceptedManifestHash` for a workspace with 1,860 files (`.git/objects` 58.5 %, one worktree) → that workspace had been uploaded;
- **`repoSnapshotIndexingEnabled=false` on that machine and the snapshot was still taken** — same as on Windows; the UI switch is not a mitigation;
- the older 3.7.7 build already contained the same pipeline, so this is not a recently introduced behaviour;
- the pipeline was *also* present in `~/.zcode/server/zcode-server.cjs` (invariant distance 527 B, same order of magnitude as the 290 B measured in the desktop bundle).

## 6. Verdict truth table

| Pipeline | accepted hash | pending | manifest | verdict |
|---|---|---|---|---|
| no | – | – | – | `FEATURE_ABSENT` |
| yes | – | – | – | `NO_LOCAL_TRACE` |
| yes | – | – | yes | `CAPTURED_NOT_ACCEPTED` |
| yes | – | yes | yes | `PACKED_PENDING` |
| yes | yes | – | yes | **`UPLOADED`** |
| yes | evidence wiped | ? | ? | `INCONCLUSIVE` |

Local physical evidence outranks the code interpreter: when signature scanning cannot confirm the pipeline (version drift, non-standard install) but an accepted record exists locally, the verdict stays `UPLOADED` with downgraded confidence and a warning — **being unable to read the client is not evidence of safety**.
