# Contributing

Thanks for helping. The most valuable contributions are the ones that keep the tool honest on machines other than the author's.

## Ground rules

1. **No new dependencies.** The tool is standard-library-only Python 3.9+. A regression test asserts this; a PR that adds an import outside the standard library will fail CI.
2. **No network code.** None. Ever.
3. **Read-only by default.** Anything that mutates system state must sit behind an explicit flag, be reversible, and verify itself with a probe.
4. **Keep `scripts/selftest.py` green on all three operating systems.** CI runs the matrix (Python 3.9 / 3.12 / 3.13 × Linux / macOS / Windows).

## The two contributions we want most

### New signature needles

When the client ships a new build, the minified code moves and existing needles stop matching. Add the new string to `NEEDLES` in `scripts/diagnose.py`:

```python
NEEDLES = {
    ...
    "new_thing": b"some-literal-from-the-bundle",
}
```

Then say which build you verified against in the PR description (version, platform, and how you found the string). If a needle no longer exists in current builds, leave it in place — older builds are still being audited — but note it.

### New payload carriers

If the pipeline code appears somewhere the tool does not look yet — a new directory inside the data root, a differently named bundle, an AppImage mount, a package-manager layout — extend `client_targets_under()` / `install_candidates()` and add a fixture case.

## Adding a fixture case

`scripts/selftest.py` builds fully synthetic trees under a temp directory and never touches a real `~/.zcode`. Add a builder plus assertions:

```python
base, home, bundle = build_posix_case(root, "16-new-layout", "linux")
r, doc = run_diag(base / "r.json", base / "r.html", ["--platform", "linux", "--home", str(home)], install_dir=bundle)
check("verdict=UPLOADED", doc and doc["verdict"]["code"] == "UPLOADED")
```

Assertions must be **locale-independent** — check `verdict.flags` (and the other JSON fields), never the rendered prose, which is localised.

## Local checks before opening a PR

```bash
python3 scripts/selftest.py               # 18 fixtures
python3 scripts/selftest.py --with-lock   # also exercises the real lock primitives
python3 scripts/diagnose.py --list-paths  # sanity-check path detection on your own machine
```

## Pull requests

- One logical change per PR, with a `CHANGELOG.md` entry under `Unreleased`.
- Explain **how you verified** on which OS/client build. "CI is green" is not verification for anything OS-specific.
- If your change affects the wording of a verdict, show the before/after report for a fixture.

## Translations

The report is generated in English and Chinese; other languages are welcome. All user-facing prose lives in the `MESSAGES` table in `scripts/diagnose.py` (204 keys per locale) — add a new locale there (keys are stable) and a `--lang` value. Do not translate inside the logic.
