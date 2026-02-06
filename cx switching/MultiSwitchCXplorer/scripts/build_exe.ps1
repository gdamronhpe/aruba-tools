# Build MultiSwitchCXplorer (one-file)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
Set-Location $root

$pyinstaller = Get-Command pyinstaller -ErrorAction SilentlyContinue
if (-not $pyinstaller) {
  Write-Error 'PyInstaller not found. Install with: pip install pyinstaller'
}

pyinstaller --onefile --windowed `
  --name MultiSwitchCXplorer `
  --icon "assets\MultiSwitchCXplorer.ico" `
  --add-data "assets\endpoints.json;assets" `
  --add-data "assets\saved_requests.json;assets" `
  --add-data "assets\MultiSwitchCXplorer.png;assets" `
  --add-data "assets\ArubaCXMultiAPI.png;assets" `
  "src\main.py"

Write-Host "Build complete. Output: $root\dist\MultiSwitchCXplorer.exe"
