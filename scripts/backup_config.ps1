# backup_config.ps1
# Binary backup of agent.toml with byte-level and TOML validation.
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
$Backups = Get-ChildItem -LiteralPath $RepoRoot -Filter 'agent.toml.bak-*' -File |
    Sort-Object LastWriteTimeUtc -Descending
if ($Backups.Count -gt $Keep) {
    $Backups | Select-Object -Skip $Keep | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Force
        Write-Output ("pruned old backup: {0}" -f $_.Name)
    }
}
