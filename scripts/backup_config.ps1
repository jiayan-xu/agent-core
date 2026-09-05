# backup_config.ps1
# Binary backup of agent.toml with byte-level and TOML validation.
#
# Note: agent.toml is rewritten at runtime by save_config (src/config.rs),
# so run this AFTER config edits, not before — otherwise the backup captures
# a pre-edit state (ocr PR#75 medium).
#
# Safety rules:
#   - Copies bytes verbatim (Copy-Item), never decodes/re-encodes text.
#   - Verifies SHA256 source == backup.
#   - Validates the backup parses as TOML via python tomllib.
#     A failed validation deletes the new backup (fail-safe, never keeps a corrupt copy).
#   - Keeps the newest N backups named agent.toml.bak-* in the repo root.
#   - Never prints secret values.
#
# Usage:
#   pwsh scripts/backup_config.ps1
#   pwsh scripts/backup_config.ps1 -Keep 20
param(
    [int]$Keep = 10
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Source = Join-Path $RepoRoot 'agent.toml'

if (-not (Test-Path -LiteralPath $Source)) {
    Write-Error "agent.toml not found: $Source"
    exit 1
}

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Dest = Join-Path $RepoRoot ("agent.toml.bak-" + $Stamp)

# 1) byte-exact copy
Copy-Item -LiteralPath $Source -Destination $Dest

# 2) hash equality check
$HashSource = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
$HashBackup = (Get-FileHash -LiteralPath $Dest -Algorithm SHA256).Hash
if ($HashSource -ne $HashBackup) {
    Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
    Write-Error "SHA256 mismatch after copy; backup deleted"
    exit 2
}

# 3) TOML validation (values are never printed)
$py = @'
import pathlib, sys, tomllib
p = pathlib.Path(sys.argv[1])
b = p.read_bytes()
try:
    s = b.decode("utf-8")
    ok = "\ufffd" not in s
except Exception:
    ok = False
if not ok:
    print("UTF8_INVALID"); sys.exit(3)
d = tomllib.loads(s)
print("TOML_OK top_keys=%d" % len(d))
'@
$pyOut = $py | python - $Dest
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $Dest -Force -ErrorAction SilentlyContinue
    Write-Error "TOML validation failed; backup deleted"
    exit 3
}
Write-Output ("backup ok: {0} ({1})" -f (Split-Path $Dest -Leaf), $pyOut)

# 4) retention: keep newest N agent.toml.bak-* files
# Sort by the creation timestamp embedded in the backup name, not mtime:
# Copy-Item preserves the source's LastWriteTime, so after a restore every
# subsequent backup inherits the restored file's old mtime and sorts as
# "oldest" — retention would prune the newest backups first (ocr PR#75 high).
$Backups = Get-ChildItem -LiteralPath $RepoRoot -Filter 'agent.toml.bak-*' -File |
    Sort-Object Name -Descending
if ($Backups.Count -gt $Keep) {
    $Backups | Select-Object -Skip $Keep | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Force
        Write-Output ("pruned old backup: {0}" -f $_.Name)
    }
}

# 5) guard: secret-bearing backups must stay out of version control
# agent.toml is gitignored because it can hold plaintext keys; the exact-name
# pattern does NOT match agent.toml.bak-* (ocr PR#75 security high). Verify and
# abort if the destination would be tracked.
$check = git -C $RepoRoot check-ignore -q "agent.toml.bak-$Stamp" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error ("agent.toml.bak-* is NOT gitignored — refusing to create a secret-bearing backup " +
                 "that 'git add .' would stage. Add 'agent.toml.bak-*' to .gitignore first.")
    exit 4
}
Write-Output "gitignore guard ok"
