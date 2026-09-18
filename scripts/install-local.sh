#!/bin/sh
# Install this skill into every skills directory that exists on this machine.
# Usage: ./scripts/install-local.sh [--dry-run]
set -eu

SRC=$(cd "$(dirname "$0")/.." && pwd)
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

for dest in "$HOME/.pi/agent/skills" "$HOME/.claude/skills" "$HOME/.agents/skills" "$HOME/.codex/skills"; do
  parent=$(dirname "$dest")
  [ -d "$parent" ] || continue
  target="$dest/zcode-upload-forensics"
  if [ "$DRY" = "1" ]; then
    echo "would install: $SRC -> $target"
    continue
  fi
  mkdir -p "$dest"
  rm -rf "$target"
  cp -R "$SRC" "$target"
  rm -rf "$target/.git" "$target/scripts/__pycache__" "$target/scripts/zcode_forensics/__pycache__"
  echo "installed: $target"
done

echo
echo "Verify with: python3 \"$SRC/scripts/selftest.py\""
