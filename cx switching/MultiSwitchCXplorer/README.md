# MultiSwitchCXplorer

A lightweight Aruba CX multi-switch explorer that runs REST API requests across many devices at once, with a clean GUI, headless CLI mode, and CSV export.

## Features
- Saved Requests and Custom Requests tabs
- Parallel requests with concurrency control
- JSON tree viewer, raw response, and logs
- CSV export (filtered or full)
- Headless mode for automation
- Windows-focused, works cross-platform with Python

## Requirements
- Python 3.10+
- `requests`
- `ttkbootstrap`

Install dependencies:

```powershell
pip install requests ttkbootstrap
```

## Run from Source

From the project root:

```powershell
python .\src\main.py
```

## Build the EXE (one-file)

```powershell
.\scripts\build_exe.ps1
```

The EXE will be in `dist\MultiSwitchCXplorer.exe`.

## Usage (GUI)
1. Add Target Switches (one per line)
2. Enter credentials
3. Choose Saved Request or Custom Request
4. Click **Run API Requests**

## Usage (CLI)

### Headless

```powershell
MultiSwitchCXplorer.exe --headless --username admin --password "P@ssw0rd!" --device 192.168.1.12 --endpoint system --version 10.11 --depth 1 --verifyssl false --concurrency 10 --output .\results.csv
```

### GUI autofill

```powershell
MultiSwitchCXplorer.exe --username admin --device-file .\switches.txt --endpoint system/interfaces --selector status --version 10.15 --depth 2 --verifyssl true --concurrency 8
```

## Project Layout
```
MultiSwitchCXplorer/
  assets/
  scripts/
  src/
```

## Notes
- `saved_requests.json` is stored next to the EXE at runtime and is created if missing.
- `endpoints.json` is bundled for endpoint metadata.

## License
Internal use. Add a license if you plan to publish publicly.
