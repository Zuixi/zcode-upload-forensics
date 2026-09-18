# Install this skill into every skills directory that exists on this machine.
# Usage: powershell -File scripts\install-local.ps1 [-DryRun]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'
$src = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$home_ = $env:USERPROFILE

$targets = @(
    (Join-Path $home_ '.pi\agent\skills'),
    (Join-Path $home_ '.claude\skills'),
    (Join-Path $home_ '.agents\skills'),
    (Join-Path $home_ '.codex\skills')
)

foreach ($dest in $targets) {
    $parent = Split-Path $dest -Parent
    if (-not (Test-Path $parent)) { continue }
    $target = Join-Path $dest 'zcode-upload-forensics'
    if ($DryRun) { Write-Host "would install: $src -> $target"; continue }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Copy-Item -Recurse -Force $src $target
    Remove-Item -Recurse -Force (Join-Path $target '.git') -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $target 'scripts\__pycache__') -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $target 'scripts\zcode_forensics\__pycache__') -ErrorAction SilentlyContinue
    Write-Host "installed: $target"
}

Write-Host ''
Write-Host "Verify with: python `"$src\scripts\selftest.py`""
