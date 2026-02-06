# Release Notes

## 2026.02.06
- UI refresh with ttkbootstrap dark theme
- Header title with Aruba-style accent and Help button
- Saved Requests: alphabetized list, right-click delete, and delete button
- Custom Request: save button placed above Recent Requests
- Run button styling: orange default, red while running, fixed size
- Results area grouped and aligned with Connection Targets
- CLI: support `--device` for single-host headless runs
- Saved Requests stored next to EXE, seeded from assets on first run
- Build script updated for new src/assets layout

### Known Notes
- One-file builds still unpack to a temp folder each run (expected PyInstaller behavior)
