$ErrorActionPreference = "Stop"
$repoDir = "C:\Users\user\agent-core"
$exe = Join-Path $repoDir "target\release\agent-core.exe"
$new = "C:\Users\user\agent-core\target-deploy\release\agent-core.exe"

# ---- 预检（ocr PR#70 第三轮 high：先验证载荷再停服务；失败路径要能回去）----
if (-not (Test-Path $new)) { Write-Output "FATAL: 新包不存在 $new"; exit 1 }
if ((Get-Item $new).Length -lt 1MB) { Write-Output "FATAL: 新包疑似截断（<1MB）"; exit 1 }
if (Test-Path $exe) { Copy-Item $exe "$exe.goodbak" -Force }

# ---- 停服务：仅按映像名（CommandLine 匹配会误杀命令行含该路径的看门狗/包装进程）----
$done = $false
for ($i = 0; $i -lt 6 -and -not $done; $i++) {
    Get-Process -Name "agent-core" -ErrorAction SilentlyContinue |
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
if (-not $done) {
    Write-Output "copy 失败×6：回滚在位 exe"
    Get-Process -Name "agent-core" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Copy-Item "$exe.goodbak" $exe -Force
    exit 1
}

# ---- 启动：仓库文档要求从仓库根启动（cwd=repoDir；全部持久化状态按 cwd 解析，
# ---- target\release 启动会生成全新空状态，等同数据丢失——ocr PR#70 第三轮 high）----
Get-Content (Join-Path $env:USERPROFILE ".svc-secrets\agent-core.env") |
    Where-Object { $_ -match "^([A-Z_0-9]+)=(.+)$" } |
    ForEach-Object { Set-Item -Path ("env:" + $Matches[1]) -Value $Matches[2].Trim() }
Start-Process $exe -ArgumentList "--service" -WorkingDirectory $repoDir -WindowStyle Hidden

# ---- 验证：30s 内 /health 必须 200，否则回滚（不宣称未经证实的成功）----
$up = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:9753/health" -TimeoutSec 3 -UseBasicParsing
        if ($r.StatusCode -eq 200) { $up = $true; break }
    } catch { }
}
if ($up) {
    Write-Output "deploy OK: /health 200"
} else {
    Write-Output "deploy 后 /health 未恢复：回滚 goodbak"
    Get-Process -Name "agent-core" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Copy-Item "$exe.goodbak" $exe -Force
    Start-Process $exe -ArgumentList "--service" -WorkingDirectory $repoDir -WindowStyle Hidden
    exit 1
}
