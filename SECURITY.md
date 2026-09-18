# Security policy

## Scope

This project is a **read-only forensic tool**. It inspects local files written by the ZCode client and inspects the client's own JavaScript bundle for known signatures.

It deliberately does not:

- open a network connection of any kind;
- decrypt or attempt to decrypt encrypted artifacts;
- read the contents of files inside your workspaces (only manifests, client settings, and presence/size metadata);
- delete or modify anything, including during the optional lock step (which moves evidence to a quarantine directory).

## Reporting a vulnerability

Open a private security advisory on GitHub (Security → Advisories → *Report a vulnerability*). Please do not open a public issue for anything that could be used to attack someone else's machine.

Useful reports include:

- a way to make the tool **write** to, or destroy, files outside a temp directory;
- a way to make it **leak** data (network, report contents, telemetry);
- a path-traversal or symlink issue in the evidence walker;
- a way to make it report `UPLOADED` when nothing was uploaded, or a clean verdict when evidence was destroyed.

## Handling of the generated report

The HTML/JSON report contains repository paths, branch names, worktree names and internal remote host names. Treat it as confidential. Use `--redact` before sharing anything, and never attach an unredacted report to a public issue — the issue template asks for the `--json` output *after* redaction.
