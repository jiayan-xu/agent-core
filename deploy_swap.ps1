$ErrorActionPreference = "Continue"
$exe = "C:\Users\user\agent-core\target\release\agent-core.exe"
$new = "C:\Users\user\agent-core\target-deploy\release\agent-core.exe"

# 带重试的换装：托盘 30s 心跳可能抢先补拉旧 exe 并锁文件 → 再杀再试。
# 停止模式精确到 agent-core.exe 且排除自身（本脚本路径含 agent-core，
# 宽泛匹配会自杀——第一版脚本就是这样无声退出的）
$done = $false
for ($i = 0; $i -lt 6 -and -not $done; $i++) {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match "agent-core\.exe" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-Process -Name "agent-core" -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -ne $PID } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 900
    try {
        Copy-Item $new $exe -Force -ErrorAction Stop
        $done = $true
        Write-Output "copy OK (attempt $($i + 1))"
    } catch {
        Write-Output "copy failed (attempt $($i + 1)): $($_.Exception.Message)"
        Start-Sleep -Seconds 2
    }
}
if (-not $done) { Write-Output "FATAL: copy never succeeded"; exit 1 }

# 托盘同款：注入 env 后启动 --service，cwd=target\release
Get-Content "$env:USERPROFILE\.svc-secrets\agent-core.env" | ForEach-Object {
    if ($_ -match "^([A-Z_0-9]+)=(.*)$") {
        Set-Item -Path ("env:" + $Matches[1]) -Value $Matches[2].Trim()
    }
}
Start-Process $exe -ArgumentList "--service" -WorkingDirectory (Split-Path $exe) -WindowStyle Hidden
Write-Output "started new exe"
