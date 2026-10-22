<#
.SYNOPSIS
    把 agent-core 安装为 Windows 服务（开机自启 + 崩溃自动重启）。

.DESCRIPTION
    P2 阶段3：agent-core 承担了本机服务编排职责后，自身不能再依赖 GUI 托盘拉起——
    托盘崩溃 / 未登录桌面 / 被误杀，整条服务保活链就断了。

    本脚本在 `--install-service` 之外还做两件事：
      1. 把 ~/.svc-secrets/agent-core.env 注入服务注册表。
         SCM 启动的进程**不继承**用户会话环境，不注入的话服务会缺 MEMORIA_ADMIN_KEY
         等变量，表现为 memoria 不可达、命名空间回退（静默降级，很难发现）。
      2. 端口占用保护（9753 已被占用时不启动，避免起不来还查不出原因）。

.PARAMETER Uninstall
    卸载服务（同时清理注入的环境变量）。

.EXAMPLE
    .\install_service.ps1
    .\install_service.ps1 -Uninstall

.NOTES
    需以管理员身份运行。文件保存为 UTF-8 with BOM，PowerShell 5.1 才能正确显示中文。
#>
#Requires -RunAsAdministrator
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $repo 'target\release\agent-core.exe'
$svc = 'agent-core'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
$port = 9753
$envFile = Join-Path $env:USERPROFILE '.svc-secrets\agent-core.env'

Write-Host '=== agent-core Windows 服务 ===' -ForegroundColor Cyan

if ($Uninstall) {
    Write-Host '停止服务...'
    sc.exe stop $svc 2>&1 | Out-Host
    Start-Sleep -Seconds 3
    if (-not (Test-Path $exe)) {
        Write-Host "x 找不到 exe: $exe" -ForegroundColor Red
        Write-Host '  可手动删除: sc.exe delete agent-core' -ForegroundColor Yellow
        exit 1
    }
    & $exe --uninstall-service
    if (Test-Path $regPath) {
        Remove-ItemProperty -Path $regPath -Name Environment -ErrorAction SilentlyContinue
    }
    exit $LASTEXITCODE
}

if (-not (Test-Path $exe)) {
    Write-Host "x 找不到 exe: $exe" -ForegroundColor Red
    Write-Host '  先执行: cargo build --release --bin agent-core' -ForegroundColor Yellow
    exit 1
}
Write-Host "exe: $exe`n"

# 1) 注册服务 + 崩溃重启策略（由 exe 内部调 SCM API 完成）
& $exe --install-service
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2) 注入环境变量：SCM 启动的进程没有用户会话环境
if (Test-Path $envFile) {
    $lines = @(
        Get-Content $envFile |
        Where-Object { $_ -match '^\s*[A-Za-z_][A-Za-z0-9_]*=' } |
        ForEach-Object { $_.Trim() }
    )
    if ($lines.Count -gt 0 -and (Test-Path $regPath)) {
        New-ItemProperty -Path $regPath -Name Environment -PropertyType MultiString `
            -Value $lines -Force | Out-Null
        Write-Host "OK 已注入 $($lines.Count) 个环境变量到服务注册表" -ForegroundColor Green
    }
} else {
    Write-Host "! 未找到 $envFile（服务可能以降级状态运行）" -ForegroundColor Yellow
}

# 3) 端口占用保护
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

# 4) 启动 + 探活
Write-Host "`n启动服务..." -ForegroundColor Cyan
sc.exe start $svc 2>&1 | Out-Host
Start-Sleep -Seconds 5
sc.exe query $svc 2>&1 | Out-Host

try {
    $h = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health" -TimeoutSec 10
    Write-Host "`nOK 服务就绪: v$($h.version) status=$($h.status) memoria=$($h.memoria.reachable)" -ForegroundColor Green
    Write-Host '   开机会自动启动；崩溃由 SCM 自动重启。' -ForegroundColor Gray
    Write-Host '   托盘服务表里把 agent-core 标为 managed_by=agent-core，避免双管理者。' -ForegroundColor Gray
} catch {
    Write-Host "`n! 服务已启动但 /health 无响应，请查看日志后再判断" -ForegroundColor Yellow
}
