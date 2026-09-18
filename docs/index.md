---
title: zcode-upload-forensics
---

<style>
  :root { color-scheme: light dark; }
  body { max-width: 46rem; margin: 0 auto; padding: 2.5rem 1.25rem 5rem;
         font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans SC", sans-serif; }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
  p.lead { font-size: 1.05rem; margin-top: 0; }
  ul { padding-left: 1.2rem; }
  li { margin: .4rem 0; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em;
         background: rgba(127,127,127,.14); padding: .1em .35em; border-radius: 4px; }
  .note { border-left: 3px solid rgba(127,127,127,.4); padding-left: .9rem; margin: 1.6rem 0;
          font-size: .93rem; opacity: .85; }
</style>

# zcode-upload-forensics

An agent skill that answers one question with evidence: **did the ZCode desktop client silently pack my
workspaces — including full Git history — and upload them to a vendor object store?**

## What to look at

- **[Example report](sample-report.html)** — a full rendered report, generated from a synthetic fixture
  with `--redact paths`, so it contains no real paths, hashes or branch names.
- **[Findings](findings.md)** — what was measured, on which client builds, how, and what remains unverified.
- **[Repository](https://github.com/Zuixi/zcode-upload-forensics)** — source, README, install instructions,
  [platform lock recipes](https://github.com/Zuixi/zcode-upload-forensics/blob/main/references/platform-locks.md)
  and [field semantics](https://github.com/Zuixi/zcode-upload-forensics/blob/main/references/evidence-map.md).

## Quick start

```bash
npx skills add Zuixi/zcode-upload-forensics          # skills CLI
git clone https://github.com/Zuixi/zcode-upload-forensics && cd zcode-upload-forensics
python3 scripts/diagnose.py --out ./zcode-upload-report.html
```

<p class="note">Read-only by default: no network access, no decryption, no workspace file contents, and
nothing is deleted. The report contains repository paths, branch names and internal host names — treat it
as confidential and use <code>--redact</code> before sharing. MIT licensed; not affiliated with Zhipu / Z.ai.</p>
