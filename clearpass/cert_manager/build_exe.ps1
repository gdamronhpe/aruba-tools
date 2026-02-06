param(
  [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

Write-Host "Building ClearPass Certificate Manager (Web) EXE..."

python -m pip install --upgrade pip
python -m pip install pyinstaller

pyinstaller `
  --onefile `
  --name CPPM_CertMgr_Web `
  --distpath $OutDir `
  --workpath build `
  --specpath build `
  clearpass\cert_manager\CPPM_CertMgr_Web.py

Write-Host "Done. Output: $OutDir\CPPM_CertMgr_Web.exe"
