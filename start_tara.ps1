# Starts TARA: the authorization server (with its approval window) and the voice side.
#   Default:     voice via xiaozhi.me, TARA tools (laptop agent, approvals, laptop music) over its MCP endpoint
#   -SelfHosted: self-hosted XiaoZhi voice server on this laptop (board's OTA URL must point here)
# Run:  powershell -ExecutionPolicy Bypass -File C:\Users\manju\tara\start_tara.ps1
param([switch]$SelfHosted)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
# Reload PATH from Windows so newly installed tools (e.g. ffmpeg) are found.
$env:PATH = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
$py = "C:\Python312\python.exe"
$server = "C:\Users\manju\xiaozhi-esp32-server\main\xiaozhi-server"
$serverPy = "$server\.venv\Scripts\python.exe"

# Keep the authorization server alive: if it ever exits, start it again (the agent is blocked while it is down).
Start-Process powershell -WindowStyle Minimized -WorkingDirectory "$root\tara" -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'TARA authorization server'; " +
    "while (`$true) { & '$py' '$root\tara\server.py' 2>> '$root\audit\server-stderr.log'; " +
    "Add-Content '$root\audit\server-stderr.log' ((Get-Date -Format s) + ' server exited; restarting'); Start-Sleep 2 }")
Start-Sleep -Seconds 3

if (-not $SelfHosted) {
    Start-Process powershell -WorkingDirectory "$root\tara" -ArgumentList @(
        "-NoExit", "-Command",
        "`$host.UI.RawUI.WindowTitle = 'TARA voice bridge (xiaozhi.me)'; & '$py' '$root\tara\voice_bridge.py'")
    Write-Host "TARA started: approval window + xiaozhi.me bridge."
    return
}

# opus.dll (audio codec) ships inside the PyOgg package; the voice server needs it on PATH.
$opus = & $serverPy -c "import os, pyogg; print(os.path.dirname(pyogg.__file__))"
Start-Process powershell -WorkingDirectory $server -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'TARA voice server'; `$env:PATH = '$opus;' + `$env:PATH; " +
    "`$env:PYTHONIOENCODING = 'utf-8'; & '$serverPy' app.py")
Write-Host "TARA started: approval window + self-hosted voice server."
Write-Host "Board OTA address: http://192.168.1.205:8003/xiaozhi/ota/"
