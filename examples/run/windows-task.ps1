# Starts the Cloakwall proxy at logon on Windows, with no window, using a
# per-user scheduled task. Run once in PowerShell:
#
#   pip install cloakwall
#   [Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-...", "User")
#   powershell -ExecutionPolicy Bypass -File windows-task.ps1
#
# The key is a user environment variable: visible to your account only, not
# written in the task and not on a command line. Remove the task with:
#
#   Unregister-ScheduledTask -TaskName Cloakwall -Confirm:$false

param(
    [string]$Upstream = "https://api.openai.com/v1",
    [string]$KeyVar = "OPENAI_API_KEY",
    [int]$Port = 8787,
    [ValidateSet("Interactive", "S4U")]
    [string]$LogonType = "Interactive"    # S4U: run without a logged-in session
)

$ErrorActionPreference = "Stop"
$pythonw = (Get-Command pythonw.exe).Source      # pythonw: no console window
$auditDir = Join-Path $env:LOCALAPPDATA "cloakwall"
New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
$audit = Join-Path $auditDir "audit.log"

$arguments = "-m cloakwall serve --upstream $Upstream --upstream-key-env $KeyVar " +
             "--port $Port --restore --audit-path `"$audit`""

$action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType $LogonType
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "Cloakwall" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force `
    -Description "Cloakwall redaction proxy on 127.0.0.1:$Port" | Out-Null
Start-ScheduledTask -TaskName "Cloakwall"
Write-Output "Cloakwall starts at every logon and is running now on http://127.0.0.1:$Port/v1"
