# Blocking and restoring: make the `checkpoints` directory unwritable

Goal: stop the client at the filesystem layer from writing into `<ZCODE>/v2/checkpoints`, cutting the "pack → drop on disk → upload" chain at its first step.
**Do not fight it by deleting files**: the uploader re-packs when the artifact disappears and increments `failureCount` (measured).

## 0. One entry point for all three platforms (off by default, needs confirmation)

```bash
python3 scripts/diagnose.py --verify-lock   # probe only: exit 0 = locked, 1 = writable
python3 scripts/diagnose.py --apply-lock    # quarantine + lock + write-probe verification (--yes for non-interactive)
python3 scripts/diagnose.py --unlock        # restore write access
```

`--apply-lock` works by **quarantine first, lock second** (it never deletes):

1. move the whole `checkpoints` directory to `checkpoints-quarantine-<timestamp>`, **keeping every `.enc` / `state.json`** for later inspection or disposal;
2. create a fresh empty `checkpoints` directory;
3. apply the write lock;
4. write a probe file into the directory — it **must fail**, otherwise the block is not in effect (prints `blocked` / `NOT blocked`).

Exit the client before locking (the script refuses to proceed while the process runs; `--force` overrides that).

## 1. Per-platform commands and verification

### Windows (deny write via ACL)

```bat
rmdir /s /q "%USERPROFILE%\.zcode\v2\checkpoints"
mkdir "%USERPROFILE%\.zcode\v2\checkpoints"
icacls "%USERPROFILE%\.zcode\v2\checkpoints" /inheritance:r ^
  /grant:r "%USERNAME%:(OI)(CI)(RX)" /grant:r "SYSTEM:(OI)(CI)(F)" /grant:r "Administrators:(OI)(CI)(F)"
icacls "%USERPROFILE%\.zcode\v2\checkpoints" /deny "%USERNAME%:(OI)(CI)(W,D)"
:: verify: this must be rejected
echo x > "%USERPROFILE%\.zcode\v2\checkpoints\probe"
```

Restore: `icacls "%USERPROFILE%\.zcode\v2\checkpoints" /reset /T`

`/inheritance:r` breaks inheritance; the user keeps `RX` (read/list, so the client can still read old state without erroring) while SYSTEM/Administrators keep `F` for recovery.

**The `/deny` line is not optional.** An allow-only ACL is silently ineffective whenever the account is a member of `Administrators` — the Windows default, and the case on CI runners — because the token also carries that group's `F` allow ACE, so the directory stays writable. An explicit deny for the user's own SID outranks every allow ACE and blocks writes from an elevated token too. This gap was found by the `real lock (windows-latest)` CI job, which runs as an administrator; every local test on a non-admin account had passed. The tool always re-checks with a write probe and reports `NOT blocked` (exit 1) rather than claiming success.

### macOS (immutable flag)

```bash
rm -rf ~/.zcode/v2/checkpoints && mkdir -p ~/.zcode/v2/checkpoints
chflags uchg ~/.zcode/v2/checkpoints
# verify: must print "Operation not permitted"
touch ~/.zcode/v2/checkpoints/probe
```

Restore: `chflags nouchg ~/.zcode/v2/checkpoints`

### Linux (immutable attribute, needs root)

```bash
sudo rm -rf ~/.zcode/v2/checkpoints && sudo mkdir -p ~/.zcode/v2/checkpoints
sudo chattr +i ~/.zcode/v2/checkpoints
# verify: must print "Operation not permitted"
touch ~/.zcode/v2/checkpoints/probe
```

Restore: `sudo chattr -i ~/.zcode/v2/checkpoints`
Without root, use ACLs instead: `setfacl -m u::rx -m g::--- -m o::--- ~/.zcode/v2/checkpoints`, or simply do not sign in.

## 2. Impact and recovery

| Item | Consequence |
|---|---|
| Blocking effect | packing cannot be written → no artifact → nothing to upload to OSS |
| Functional impact | ZCode's checkpoint rollback / timeline is unavailable; completion, chat and tool calls are unaffected |
| Log noise | the client swallows the I/O errors (the `repo-snapshot-upload` sidecar does not log at all) |
| Recovery | see above; the quarantine directory is never cleaned automatically, so evidence can be kept indefinitely |
| Upgrade / uninstall | upgrades do not remove `<ZCODE>`; re-run `--verify-lock` after an upgrade to confirm the lock survived |

## 3. Degraded options (when locking is not possible)

- do not open sensitive repositories in the client (remove them from `recentProjects` / `lastWorkspaceSession`);
- run the client under a separate OS account or in a dedicated VM, isolated from the main workspace;
- stay signed out: without a JWT, `captureBeforePrompt` returns before it even requests credentials.

## 4. Handling data that has already been uploaded

The ciphertext **cannot be recalled**: the AES key is wrapped with an RSA public key issued by the server, and the private key only exists in the cloud — it cannot be decrypted locally, and individual objects cannot be deleted. Treat it as "source code plus full Git history has left the machine":

- rotate any token, password or internal credential that ever appeared in history (`git log -p -S'<keyword>' --all` for a full-history sweep);
- review internal remote host names and private repository paths from `.git/config` (they aid lateral movement inside your network);
- check whether the `extra-manifests` payload carried your global `AGENTS.md`, `settings.behavior.json` or `skills.json` (internal conventions and tooling configuration).
