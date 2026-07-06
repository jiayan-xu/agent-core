$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "C:\Users\user\agent-core\target\release\agent-core.exe"
$psi.WorkingDirectory = "C:\Users\user\agent-core\temp_run"
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $false
$psi.RedirectStandardError = $false
$p = [System.Diagnostics.Process]::Start($psi)
Write-Output "Started agent-core PID: $($p.Id) on port 9754"
