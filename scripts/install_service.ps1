<#
.SYNOPSIS
    把 agent-core 安装为 Windows 服务（开机自启 + 崩溃自动重启）。

.DESCRIPTION
    P2 阶段3：agent-core 承担了本机服务编排职责后，自身不能再依赖 GUI 托盘拉起——
    托盘崩溃 / 未登录桌面 / 被误杀，整条服务保活链就断了。装成 SCM 服务后由系统托管，
    托盘只负责显示状态。

    安装会同时配置崩溃重启策略（5s / 30s / 60s，计数 24h 重置）。

.PARAMETER Uninstall
    卸载服务（服务运行中会先被标记删除，停止后彻底移除）。

.EXAMPLE
    .\install_service.ps1              # 安装并启动
    .\install_service.ps1 -Uninstall   # 卸载

.NOTES
    需以管理员身份运行。
#>
#Requires -RunAsAdministrator
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $repo 'target\release\agent-core.exe'
$svc = 'agent-core'
$port = 9753

Write-Host '=== agent-core Windows 服务 ===' -ForegroundColor Cyan

if (-not (Test-Path $exe)) {
    Write-Host "x 找不到 exe: $exe" -ForegroundColor Red
    Write-Host '  先执行: cargo build --release --bin agent-core' -ForegroundColor Yellow
    exit 1
}

if ($Uninstall) {
    Write-Host '停止服务...'
    sc.exe stop $svc | Out-Host
    Start-Sleep -Seconds 3
    & $exe --uninstall-service
    exit $LASTEXITCODE
}

Write-Host "exe: $exe`n"

# 1) 注册服务 + 崩溃重启策略（由 exe 内部调 SCM API 完成）
& $exe --install-service
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2) 端口占用检查：SCM 启动前确认没人占着 9753，避免装完起不来
$conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($conn) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($conn.OwningProcess)" -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host "! 端口 $port 已被占用（PID=$($conn.OwningProcess) $($p.Name)）" -ForegroundColor Yellow
    Write-Host '  服务已注册但未启动。请先停掉该进程（例如从托盘退出 agent-core），再执行:' -ForegroundColor Yellow
    Write-Host "    sc.exe start $svc" -ForegroundColor Yellow
    exit 0
}

# 3) 启动 + 探活
Write-Host "`n启动服务..." -ForegroundColor Cyan
sc.exe start $svc | Out-Host
Start-Sleep -Seconds 4
sc.exe query $svc | Out-Host

try {
    $h = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health" -TimeoutSec 8
    Write-Host "`nOK 服务就绪: v$($h.version)  status=$($h.status)" -ForegroundColor Green
    Write-Host "   以后开机会自动启动；崩溃由 SCM 自动重启。" -ForegroundColor Gray
    Write-Host "   托盘应从服务表里把 agent-core 标为 managed_by=agent-core，避免双管理者。" -ForegroundColor Gray
} catch {
    Write-Host "`n! 服务已启动但 /health 无响应，请查看日志后再判断" -ForegroundColor Yellow
}
