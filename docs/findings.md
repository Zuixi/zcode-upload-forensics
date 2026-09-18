# Findings: what the ZCode client does with your workspaces

This document records **what was measured, on which builds, and how** — separately from what the tool concludes. Everything here was observed on machines we own, using the read-only collector in this repository plus static inspection of the locally installed client bundle. No vendor system was queried, and no encrypted artifact was ever decrypted (that is not possible locally — see [Why the ciphertext cannot be read](#why-the-ciphertext-cannot-be-read)).

All paths, repository names, branch names and host names below are placeholders.

## Summary

When a user is signed in, the ZCode desktop client packages the workspace it has open — **including the complete `.git` directory** — encrypts it with a public key it just fetched from the vendor's server, and uploads the result directly to an object-storage bucket. The private half of that key only exists server-side, so neither the user nor the client itself can read the artifact afterwards.

Two user-facing settings look like they control this. Neither does.

## What is collected

The client writes a manifest before packing, and the manifest itself is left on disk unencrypted. Reading it tells you exactly what went into the archive. A representative manifest from one of our machines:

| Group | Share of bytes | Notes |
|---|---|---|
| `.git/objects` | 58.5 % | the complete commit/tree/blob history |
| `.git/logs` | < 1 % | reflogs, i.e. local branch operations that were never pushed |
| `.git/refs`, `.git/packed-refs` | < 1 % | every local branch name, including unpublished ones |
| `.git/worktrees/*` | ~2 % | per-worktree `index` and `logs/HEAD` |
| `.git/config` | < 1 % | remote URLs, including internal hostnames |
| working tree sources + docs | remainder | everything not ignored |

A second manifest (`repo_snapshot_extra_manifest/v1`) travels with every snapshot and carries the client's **global configuration** — `settings.behavior.json`, `skills.json` and global instruction files such as `AGENTS.md`. So the upload is not limited to the repository that happens to be open.

### Why the `.git` share matters

`.git` is the part a user cannot rotate cheaply. A working tree can be scrubbed; commit history cannot. Anything that was ever committed — a credential that was later removed, a branch name that reveals an unannounced product direction, an internal Git host in `.git/config` — is still recoverable from the objects and reflogs that were uploaded.

## The upload chain

Reconstructed from the client bundle (the code is minified but the strings and control flow are intact):

```
1. GET  https://<vendor>/api/v1/snapshot/upload-credential?workspace_id=<hash>
        -> snapshot_id, an RSA public key, an OSS form signature, a size limit
2. local: tar -> gzip -> AES-256-CTR (random key) -> RSA-OAEP-SHA256 wrap of that key
3. POST <oss-host>   multipart/form-data, file name "repo-snapshot.tar.gz.enc"
        -> straight to object storage; the vendor's own API server never sees the payload
4. OSS callback -> vendor backend records the snapshot
```

Step 3 is why a network-level block list aimed at the vendor's API domain does not stop the upload: the payload goes to a bucket host, and the coordination request in step 1 happens *before* the packing, so even a failed upload has already told the server which workspace hash exists on this machine.

### The one field the tool trusts

`<data-dir>/v2/checkpoints/<workspaceKeyHash>/state.json` holds a small ledger. The relevant field is `lastAcceptedManifestHash`. In the code it is written in exactly one place:

```
flushActiveUpload():
    d = requestUploadTarget(...)               # local only, uses the cached credential
    if !(await uploadObject(...)).ok -> failPendingUpload(...)   # does NOT write it
    markAcceptedManifest(...)                  # <- the only writer
```

`markAcceptedManifest` has two implementations and one call site, and that call site is only reachable after the object upload returned 2xx. So a non-empty `lastAcceptedManifestHash` means the ciphertext reached the bucket; an empty `pending/` directory does **not** mean nothing was sent.

The collector re-checks this adjacency in the installed bundle rather than assuming it (see `scripts/zcode_forensics/signatures.py`). When the check cannot be made — a new build moved the code — the verdict keeps its local evidence but drops to medium confidence and says so.

## Measured on two machines

| | Machine A | Machine B |
|---|---|---|
| OS | Windows | macOS 26.2 |
| Client build | 3.11.2 | 3.7.7 |
| Install location | non-default drive, found via the uninstall registry key | `/Applications` bundle |
| Pipeline signatures in the bundle | 5 / 5 | 5 / 5 |
| Invariant adjacency (`markAcceptedManifest` ⇄ `uploadObject`) | 290 B | 290 B (desktop bundle), 527 B (host bundle) |
| State ledger | `lastAcceptedManifestHash` present, `pending/` empty | same |
| `optimizeAgentExperienceEnabled` | `false` | `false` |
| `repoSnapshotIndexingEnabled` | `true` | **`false`** |
| Result | snapshot uploaded | snapshot uploaded |

Two observations from this table are worth separating from the rest:

1. **The newer build is not the problem.** The same pipeline exists in 3.7.7, so this is not a recently introduced behaviour that a downgrade would remove.
2. **Turning the "repository snapshot indexing" switch off does not stop the upload.** On machine B the switch was `false` and the ledger still recorded an accepted snapshot. Settings that gate *server-side processing* are not settings that gate *collection*.

The recorded artifacts were also far smaller than the manifests — 47 KB against a 6.4 MB manifest on one capture, 444 KB against 20.7 MB on another. `.git/objects` is already zlib-compressed, so gzip should barely shrink it; a gzip output two orders of magnitude smaller means the artifact was an **incremental delta**, which in turn means an earlier full baseline had already been accepted. A small `.enc` is not good news.

## Third machine: no desktop client

A macOS box that had only ever been used as an SSH workspace *host* had no desktop application installed, but ZCode had pushed a host bundle into `<data-dir>/server/zcode-server.cjs`. That bundle contains the same pipeline strings and the same invariant adjacency (527 B), and the machine's own `checkpoints` directory held an accepted snapshot for a path on that machine.

Practical consequence: "we never installed the client there" is not the same as "the pipeline never ran there".

## Evidence volatility (observed)

After the client exited at 23:10:54 on one machine, the `checkpoints` directory was deleted and recreated empty at 23:12:54 — creation time equal to last-write time, which rules out NTFS timestamp tunnelling. The actor was not proven (client quit-time cleanup, an updater, or a user action all remain possible), but the operational conclusion is the same: **the local window for this evidence is narrow**.

Additionally, the upload sidecar writes no logs. Neither `<data-dir>/v2/logs` nor `<data-dir>/cli/log` contains the upload endpoint or the sidecar's logger name, so logs cannot be used to decide whether an upload happened. The state ledger is the only local record, which is why this tool keeps a JSON sidecar (`--json`) and supports `--diff` for change monitoring.

## Why the ciphertext cannot be read

The content key is random per artifact and is wrapped with an RSA public key supplied by the server at upload time. The matching private key is never sent to the client. This is not a defect in the tool: the artifact is unreadable by design to everyone except the service that issued the key. A consequence worth stating plainly is that **the upload cannot be undone**. There is no local "delete from server" path and no way to enumerate what was sent.

## What we did not verify

- Whether the server retains every snapshot, or only indexes them, and for how long.
- Whether any snapshot is used for model training. The training-related switch (`optimizeAgentExperienceEnabled`) is separate from this pipeline, but that is a statement about code paths, not about policy.
- Any server-side behaviour at all: this work is entirely local and static.
- Client builds other than the two above; the tool's signature-drift path is the honest answer there.

## Reproducing this

```bash
python3 scripts/diagnose.py --list-paths      # what will be inspected, and why
python3 scripts/diagnose.py --out report.html # verdict + evidence + HTML report
python3 scripts/selftest.py                   # verifies the collector itself
```

For a manual cross-check of the two load-bearing facts:

```bash
# 1. the ledger: is there an accepted (i.e. uploaded) manifest?
find ~/.zcode/v2/checkpoints -name state.json -exec grep -H lastAcceptedManifestHash {} \;

# 2. the invariant: do the two functions still sit next to each other?
grep -a -o "markAcceptedManifest" /Applications/ZCode.app/Contents/Resources/app.asar | wc -l
```

If the first command prints nothing, that is **not** an all-clear — see [Evidence volatility](#evidence-volatility-observed). Read `references/evidence-map.md` for the field semantics behind both commands.
