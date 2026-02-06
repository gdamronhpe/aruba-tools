import tkinter as tk
import ttkbootstrap as ttk
from tkinter import scrolledtext, filedialog, messagebox, simpledialog
from pathlib import Path
import json
import argparse
import os
import sys
import getpass
from typing import Iterable
from api import run_api_calls
from utils import (
    bind_search_keys, search_raw_view, next_match, prev_match,
    insert_json_tree, apply_filter, on_tree_right_click, on_raw_right_click,
    make_run_button, export_tree_to_csv_from_tree,
    show_help_guide, log_info, log_error, configure_logger, export_results_to_csv
)
import threading # Import threading

def resource_path(relative_name: str) -> Path:
    # In a PyInstaller onefile build, data gets unpacked into sys._MEIPASS
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).resolve().parent.parent / "assets"
    return base / relative_name

def app_root_path() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent

# Your existing default list (fallback)
DEFAULT_GET_ENDPOINTS = [
    "/system",
    "/system/subsystems",
    "/system/vlans",
    "/system/interfaces",
    "/system/acls",
]

def load_get_endpoints(
    filename: str = "endpoints.json",
    *,
    prefix_base_path: bool = False,
) -> list[str]:
    """
    Load endpoints from a bundled JSON file and return only those supporting HTTP GET.
    Supports two shapes:
      1) { "base_paths": ["/rest/v10.04"], "endpoints": { "/system": {"methods": ["GET"]}, ... } }
      2) ["/system", "/system/vlans", ...]   # already filtered list
    Falls back to DEFAULT_GET_ENDPOINTS on any error.
    """
    try:
        path = resource_path(filename)
        with path.open("r", encoding="utf-8") as f:
            spec = json.load(f)

        # Case 2: already a flat list of endpoint paths
        if isinstance(spec, list):
            return _dedupe_sorted(str(p) for p in spec)

        # Case 1: object with "endpoints" dict (+ optional base_paths)
        if not isinstance(spec, dict):
            return DEFAULT_GET_ENDPOINTS

        base_paths = spec.get("base_paths") or []
        base_prefix = str(base_paths[0]) if (prefix_base_path and base_paths) else ""

        endpoints = spec.get("endpoints", {})
        if not isinstance(endpoints, dict):
            return DEFAULT_GET_ENDPOINTS

        get_only: list[str] = []
        for path_key, meta in endpoints.items():
            # tolerate minimal entries
            methods = [m.lower() for m in (meta or {}).get("methods", [])]
            if "get" in methods:
                if base_prefix:
                    # ensure exactly one slash at the join
                    joined = f"{base_prefix.rstrip('/')}/{str(path_key).lstrip('/')}"
                    get_only.append(joined)
                else:
                    get_only.append(str(path_key))

        cleaned = _dedupe_sorted(get_only)
        return cleaned or DEFAULT_GET_ENDPOINTS

    except Exception as e:
        # Optional: your logger, if present
        try:
            log_error(f"Failed to load '{filename}': {e}")
        except Exception:
            pass
        return DEFAULT_GET_ENDPOINTS

def load_endpoint_meta(filename: str = "endpoints.json") -> dict:
    """
    Load endpoint metadata (selector enums, attributes enums) from endpoints.json.
    Returns dict keyed by endpoint path (e.g., "/system/interfaces").
    """
    try:
        path = resource_path(filename)
        with path.open("r", encoding="utf-8") as f:
            spec = json.load(f)

        if not isinstance(spec, dict):
            return {}

        endpoints = spec.get("endpoints", {})
        if not isinstance(endpoints, dict):
            return {}

        selector_defaults = spec.get("selector_values") or []
        meta = {}
        for ep, info in endpoints.items():
            if not isinstance(info, dict):
                continue
            query_params = info.get("query_params") or []
            has_selector = bool(info.get("has_selector"))
            selector_values = []
            attributes_values = []

            for p in query_params:
                if not isinstance(p, dict):
                    continue
                if p.get("name") == "selector":
                    enum = p.get("enum")
                    if isinstance(enum, list) and enum:
                        selector_values = enum
                if p.get("name") == "attributes":
                    enum = p.get("enum")
                    if isinstance(enum, list) and enum:
                        attributes_values = enum

            if has_selector and not selector_values and selector_defaults:
                selector_values = list(selector_defaults)

            meta[ep] = {
                "has_selector": has_selector,
                "selector_values": selector_values,
                "attributes_values": attributes_values,
            }

        return meta
    except Exception as e:
        try:
            log_error(f"Failed to load endpoint metadata from '{filename}': {e}")
        except Exception:
            pass
        return {}

def _dedupe_sorted(items: Iterable[str]) -> list[str]:
    """Deduplicate (case-sensitive) then sort A-Z."""
    seen = set()
    out: list[str] = []
    for x in items:
        s = str(x)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return sorted(out)

DEFAULT_SAVED_REQUESTS = [
    {
        "name": "System Summary",
        "endpoint": "/system",
        "version": "10.04",
        "depth": "1",
        "selector": "",
        "attributes": "hostname,platform_name,software_version",
        "verifyssl": True,
        "concurrency": 5,
    },
    {
        "name": "Interfaces Status",
        "endpoint": "/system/interfaces",
        "version": "10.04",
        "depth": "2",
        "selector": "status",
        "attributes": "name,admin_state,oper_state,speed,duplex",
        "verifyssl": True,
        "concurrency": 5,
    },
    {
        "name": "VLANs",
        "endpoint": "/system/vlans",
        "version": "10.04",
        "depth": "2",
        "selector": "",
        "attributes": "id,name,description,admin,oper_state",
        "verifyssl": True,
        "concurrency": 5,
    },
]

def saved_requests_path() -> Path:
    return app_root_path() / "saved_requests.json"

def load_saved_requests() -> list[dict]:
    path = saved_requests_path()
    if not path.exists():
        # Try to seed from bundled assets first, then fall back to defaults
        seed = DEFAULT_SAVED_REQUESTS
        try:
            seed_path = resource_path("saved_requests.json")
            if seed_path.exists():
                seed = json.loads(seed_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        try:
            path.write_text(json.dumps(seed, indent=2), encoding="utf-8")
        except Exception as e:
            log_error(f"Failed to write default saved requests to {path}: {e}")
        return seed if isinstance(seed, list) else DEFAULT_SAVED_REQUESTS[:]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
    except Exception as e:
        log_error(f"Failed to load saved requests from {path}: {e}")
    return DEFAULT_SAVED_REQUESTS[:]

def save_saved_requests(requests_list: list[dict]) -> None:
    path = saved_requests_path()
    path.write_text(json.dumps(requests_list, indent=2), encoding="utf-8")

# Shared state containers
recent_calls = []
all_json_results = []
search_matches = []
search_current_index = [0]
api_endpoints = load_get_endpoints()
endpoint_meta = load_endpoint_meta()
APP_VERSION = "2026.02.06" # Define app version
RAW_MAX_CHARS = 200000 # Truncate raw JSON to keep UI responsive
run_button_ref = None # Global reference for the run/stop button
RUN_BUTTON_WIDTH = 22

# Parse CLI args
def parse_cli_args():
    parser = argparse.ArgumentParser(description="MultiSwitchCXplorer CLI")
    parser.add_argument("--username", help="Username for API login")
    parser.add_argument("--password", help="Password for API login")
    parser.add_argument("--device-file", help="Path to file with switch IPs")
    parser.add_argument("--device", help="Single switch IP/hostname")
    parser.add_argument("--verifyssl", choices=["true", "false"], default="true",
                        help="Enable or disable SSL verification")

    # Headless mode + output
    parser.add_argument("--headless", action="store_true",
                        help="Run without GUI and export CSV")
    parser.add_argument("--output", help="Output CSV file path (required in --headless mode)")

    # API call parameters
    parser.add_argument("--endpoint", help="REST API endpoint to query")
    parser.add_argument("--version", default="10.04",
                        help="ArubaOS-CX REST API version (e.g., 10.04, 10.08, 10.11, 10.15)")
    parser.add_argument("--depth", type=int, default=1, help="Depth parameter (1-10)")
    parser.add_argument("--selector", choices=["configuration", "status", "statistics"],
                        help="Optional selector for supported endpoints")
    parser.add_argument("--attributes", help="Comma-separated attributes (e.g., hostname,ip)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent connections (1-20)")

    return parser.parse_args()

def open_cli_builder_popup(root,
                           username_entry, password_entry, switches_entry,
                           endpoint_combobox, version_value, depth_entry,
                           selector_value, ssl_var, concurrent_spin,attributes_entry):
    """
    Opens a popup that generates a CLI command based on current GUI settings.
    Options:
      - Headless (adds --headless and --output)
      - Include password
      - Device file (browse)
    """
    exe_name = "MultiSwitchCXplorer.exe"

    win = tk.Toplevel(root)
    win.title("Generate CLI")
    win.geometry("760x520")
    win.minsize(700, 480)
    win.transient(root)
    win.grab_set()
    win.focus_set()

    # --- local helpers ---
    def current_values():
        return {
            "username": username_entry.get().strip(),
            "password": password_entry.get(),
            "switch_text": switches_entry.get("1.0", "end").strip(),
            "endpoint": endpoint_combobox.get().strip(),
            "version": version_value.get().strip(),
            "depth": depth_entry.get().strip() or "1",
            "selector": selector_value.get().strip(),
            "verifyssl": "true" if ssl_var.get() else "false",
            "concurrency": (concurrent_spin.get() or "5").strip(),
            "attributes": attributes_entry.get().strip(),
        }

    def build_command():
        vals = current_values()

        # base flags (GUI autofill)
        parts = [exe_name]

        if vals["username"]:
            parts += ["--username", quote_arg(vals["username"])]

        if include_password_var.get():
            if vals["password"]:
                parts += ["--password", quote_arg(vals["password"])]
            else:
                # If user asked to include, but field empty, add placeholder
                parts += ["--password", quote_arg("YOUR_PASSWORD")]

        # device-file handling
        device_file = devicefile_var.get().strip()
        if device_file:
            parts += ["--device-file", quote_arg(device_file)]

        # Common API params
        if vals["endpoint"]:
            parts += ["--endpoint", quote_arg(vals["endpoint"])]
        if vals["version"]:
            parts += ["--version", quote_arg(vals["version"])]
        if vals["depth"]:
            parts += ["--depth", quote_arg(vals["depth"])]
        if vals["selector"]:
            parts += ["--selector", quote_arg(vals["selector"])]
        if vals["attributes"]:
            parts += ["--attributes", quote_arg(vals["attributes"])]

        parts += ["--verifyssl", vals["verifyssl"]]

        if vals["concurrency"]:
            parts += ["--concurrency", quote_arg(vals["concurrency"])]

        # Headless additions
        if headless_var.get():
            parts.append("--headless")
            out_path = output_var.get().strip() or ".\\results.csv"
            parts += ["--output", quote_arg(out_path)]

            # Headless requires device-file; warn if missing
            if not device_file:
                headless_hint.set("Headless requires --device-file. Please select one.")
            else:
                headless_hint.set("")
        else:
            headless_hint.set("")

        # Format with line continuations for readability
        return wrap_cmd_windows(parts)

    def wrap_cmd_windows(parts):
        # Produce multi-line Windows command using ^ continuations
        # e.g. exe --flag value ^\n  --flag value ^\n  --flag value
        lines = []
        line = []
        current_len = 0
        for token in parts:
            t = str(token)
            # group tokens into lines ~100 chars
            if current_len + 1 + len(t) > 100 and line:
                lines.append(" ".join(line) + " ^")
                line = [t]
                current_len = len(t)
            else:
                if line:
                    line.append(t)
                    current_len += 1 + len(t)
                else:
                    line = [t]
                    current_len = len(t)
        if line:
            lines.append(" ".join(line))
        return "\n  ".join(lines)

    def quote_arg(s):
        # Always quote to be safe for spaces/specials
        if s is None:
            return '""'
        s = str(s)
        if s.startswith('"') and s.endswith('"'):
            return s
        return f'"{s}"'

    def choose_device_file():
        path = filedialog.askopenfilename(
            title="Choose device file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            devicefile_var.set(path)
            refresh()

    def choose_output_file():
        path = filedialog.asksaveasfilename(
            title="Choose output CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")])
        if path:
            output_var.set(path)
            refresh()

    def copy_to_clipboard():
        cmd = preview_text.get("1.0", "end").strip()
        if not cmd:
            return
        win.clipboard_clear()
        win.clipboard_append(cmd)
        messagebox.showinfo("Copied", "Command copied to clipboard.")

    def save_bat():
        cmd = preview_text.get("1.0", "end").strip()
        if not cmd:
            messagebox.showwarning("Nothing to save", "No command to save.")
            return
        path = filedialog.asksaveasfilename(
            title="Save batch file",
            defaultextension=".bat",
            filetypes=[("Batch files", "*.bat")],
            initialfile="run-MultiSwitchCXplorer.bat"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(cmd + "\r\n")
            messagebox.showinfo("Saved", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save failed", f"Could not save file:\n{e}")

    def save_current_switches():
        # Grab the current switches from the GUI
        switch_text = switches_entry.get("1.0", "end").strip()
        if not switch_text:
            messagebox.showwarning("No switches", "The switch list is empty.")
            return
        # Choose a file to save
        path = filedialog.asksaveasfilename(
            title="Save switches list",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile="switches.txt"
        )
        if not path:
            return
        try:
            # Normalize newlines to Windows CRLF for .bat friendliness
            with open(path, "w", encoding="utf-8", newline="\r\n") as f:
                # Ensure one per line
                lines = [ln.strip() for ln in switch_text.splitlines() if ln.strip()]
                f.write("\r\n".join(lines) + "\r\n")
            # Point device-file to the saved path and refresh command
            devicefile_var.set(path)
            refresh()
            messagebox.showinfo("Saved", f"Switch list saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Save failed", f"Could not save switch list:\n{e}")


    def refresh(*_):
        # Update visibility of output row based on headless
        state = ("normal" if headless_var.get() else "disabled")
        output_entry.config(state=state)
        output_btn.config(state=state)
        # Update label hint
        hint_lbl.config(fg="red" if headless_var.get() and not devicefile_var.get().strip() else "gray")
        # Update preview
        preview_text.config(state="normal")
        preview_text.delete("1.0", "end")
        preview_text.insert("1.0", build_command() + "\n")
        preview_text.config(state="disabled")

    # --- layout ---
    frm = ttk.Frame(win)
    frm.pack(fill="both", expand=True, padx=12, pady=12)

    # Row 0: options
    opt_frame = ttk.LabelFrame(frm, text="Options")
    opt_frame.pack(fill="x", pady=(0, 10))

    headless_var = tk.BooleanVar(value=False)
    include_password_var = tk.BooleanVar(value=False)
    devicefile_var = tk.StringVar(value="")
    output_var = tk.StringVar(value=".\\results.csv")
    headless_hint = tk.StringVar(value="")

    ttk.Checkbutton(opt_frame, text="Headless (add --headless & --output)", variable=headless_var,
                    command=refresh).grid(row=0, column=0, sticky="w", padx=8, pady=6)
    ttk.Checkbutton(opt_frame, text="Include password (--password)", variable=include_password_var,
                    command=refresh).grid(row=0, column=1, sticky="w", padx=8, pady=6)

    ttk.Label(opt_frame, text="Device file:").grid(row=1, column=0, sticky="e", padx=(8, 4), pady=6)
    device_entry = ttk.Entry(opt_frame, textvariable=devicefile_var, width=50)
    device_entry.grid(row=1, column=1, sticky="we", padx=(0, 4), pady=6)

    # Buttons on the right of the device file row
    btns_dev = ttk.Frame(opt_frame)
    btns_dev.grid(row=1, column=2, sticky="w", padx=4, pady=6)
    ttk.Button(btns_dev, text="Browse...", command=choose_device_file).pack(side="left")
    ttk.Button(btns_dev, text="Save switches...", command=save_current_switches).pack(side="left", padx=(6, 0))


    ttk.Label(opt_frame, text="Output CSV:").grid(row=2, column=0, sticky="e", padx=(8, 4), pady=6)
    output_entry = ttk.Entry(opt_frame, textvariable=output_var, width=50)
    output_entry.grid(row=2, column=1, sticky="we", padx=(0, 4), pady=6)
    output_btn = ttk.Button(opt_frame, text="Browse...", command=choose_output_file)
    output_btn.grid(row=2, column=2, sticky="w", padx=4, pady=6)

    hint_lbl = tk.Label(opt_frame, textvariable=headless_hint, anchor="w", fg="gray")
    hint_lbl.grid(row=3, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 6))

    opt_frame.columnconfigure(1, weight=1)

    # Row 1: preview
    prev_frame = ttk.LabelFrame(frm, text="Command (copy or save)")
    prev_frame.pack(fill="both", expand=True)

    preview_text = scrolledtext.ScrolledText(prev_frame, wrap="none", height=12, font=("Consolas", 10))
    preview_text.pack(fill="both", expand=True, padx=8, pady=8)
    preview_text.config(state="disabled", cursor="xterm")

    # Row 2: actions
    btn_frame = ttk.Frame(frm)
    btn_frame.pack(fill="x", pady=(10, 0))
    ttk.Button(btn_frame, text="Copy", command=copy_to_clipboard).pack(side="left")
    ttk.Button(btn_frame, text="Save .bat...", command=save_bat).pack(side="left", padx=6)
    ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side="right")

    # Initialize preview visibility
    refresh()


# GUI launch
def launch_ui():
    global raw_text, raw_search_entry, raw_match_label
    global endpoint_combobox, version_value, depth_entry, selector_value, selector_combobox
    global username_entry, password_entry, switches_entry
    global recent_combo, concurrent_spin, ssl_var, tree, filter_entry
    global run_button_ref, log_text # Add log_text here
    global stat_success_var, stat_fail_var, stat_total_var, failed_switches, retry_btn
    stop_event = threading.Event() # Global stop event

    cli_args = parse_cli_args()

    # ---- Headless mode ------------------------------------------------------
    if cli_args.headless:
        # Validate required inputs
        if cli_args.device and cli_args.device_file:
            print("ERROR: Use either --device or --device-file, not both.")
            sys.exit(2)
        if not cli_args.device and (not cli_args.device_file or not os.path.isfile(cli_args.device_file)):
            print("ERROR: --device or --device-file is required for --headless.")
            sys.exit(2)
        if not cli_args.output:
            print("ERROR: --output is required for --headless.")
            sys.exit(2)
        if not cli_args.username:
            print("ERROR: --username is required for --headless.")
            sys.exit(2)

        # Assemble params
        if cli_args.device:
            switches = [cli_args.device.strip()]
        else:
            with open(cli_args.device_file) as f:
                switches = [line.strip() for line in f.read().splitlines() if line.strip()]

        username = cli_args.username
        if cli_args.password:
            password = cli_args.password
        else:
            password = getpass.getpass(prompt=f"Password for {username}: ")
        endpoint = cli_args.endpoint or api_endpoints[0]
        version = cli_args.version
        depth = str(cli_args.depth if cli_args.depth else 1)
        selector = cli_args.selector or ""
        attributes = (cli_args.attributes or "").strip()
        verify_ssl = (cli_args.verifyssl.lower() == "true")
        concurrency = max(1, min(int(cli_args.concurrency or 5), 20))

        # Collect results
        results = []
        success = 0
        failed = 0

        def on_result(switch, data, hostname):
            nonlocal success, failed
            title = f"{hostname}: {switch} - {endpoint}"
            if isinstance(data, dict):
                data["__title__"] = title
            results.append(data)
            if isinstance(data, dict) and "error" in data:
                failed += 1
            else:
                success += 1

        def on_progress(done, total):
            # Optional: print progress to console
            print(f"Progress: {done}/{total}")

        # Run synchronously (no GUI, no threads beyond api pool)
        stop_evt = threading.Event()
        print("Starting headless run...")
        run_api_calls(
            switches=switches,
            username=username,
            password=password,
            endpoint=endpoint,
            version=version,
            depth=depth,
            selector=selector,
            verify_ssl=verify_ssl,
            on_result=on_result,
            on_progress=on_progress,
            stop_event=stop_evt,
            concurrency=concurrency,
            attributes=attributes
        )

        # Export CSV
        try:
            export_results_to_csv(results, cli_args.output)
            print(f"CSV written to: {cli_args.output}")
            print(f"Summary - Success: {success}, Failed: {failed}, Total: {len(switches)}")
            sys.exit(0)
        except Exception as e:
            print(f"ERROR: Failed to write CSV: {e}")
            sys.exit(1)
    # -------------------------------------------------------------------------


    root = ttk.Window(themename="darkly")
    style = ttk.Style()
    # Aruba-like orange accent for headings and primary actions
    style.configure("TLabelFrame.Label", foreground="#F58220")
    style.configure("Accent.TButton", foreground="white", background="#F58220")
    style.configure("PrimaryAction.TButton", foreground="white", background="#F58220", font=("Segoe UI", 12, "bold"), padding=(16, 10))
    style.configure("RunDanger.TButton", foreground="white", background="#C62828", font=("Segoe UI", 12, "bold"), padding=(16, 10))
    style.configure("SecondaryAction.TButton", font=("Segoe UI", 9), padding=(6, 4))
    root.title("MultiSwitchCXplorer - Aruba CX multi-switch tool")

    stat_success_var = tk.StringVar(value="0")
    stat_fail_var = tk.StringVar(value="0")
    stat_total_var = tk.StringVar(value="0")
    failed_switches = []

    # --- Start of icon handling modification ---
    icon_path = resource_path("MultiSwitchCXplorer.ico")
    if icon_path.exists():
        root.iconbitmap(default=icon_path)
    # --- End of icon handling modification ---

    # Header
    header_frame = ttk.Frame(root)
    header_frame.pack(fill=tk.X, padx=12, pady=(8, 4))

    title_frame = ttk.Frame(header_frame)
    title_frame.pack(side=tk.LEFT, anchor="w")
    ttk.Label(title_frame, text="MultiSwitch", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
    ttk.Label(title_frame, text="CX", font=("Segoe UI", 14, "bold"), foreground="#F58220").pack(side=tk.LEFT)
    ttk.Label(title_frame, text="plorer", font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)

    # Help button top-right of the entire window
    help_btn = tk.Button(header_frame, text="Help", command=lambda: show_help_guide(APP_VERSION), font=("Arial", 8, "bold"), relief="flat", bg="lightgray")
    help_btn.pack(side=tk.RIGHT)

    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True)

    controls_frame = tk.Frame(main_frame)
    controls_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=8)

    results_frame = ttk.LabelFrame(main_frame, text="Results")
    results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=8)
    tab_control = ttk.Notebook(results_frame)
    tab_control.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    # Grouping: connection targets vs data requests
    connect_group = ttk.LabelFrame(controls_frame, text="Connection Targets")
    connect_group.pack(fill=tk.X, padx=6, pady=(6, 4))

    data_group = ttk.LabelFrame(controls_frame, text="Data Requests")
    data_group.pack(fill=tk.X, padx=6, pady=4)


    # Switches input
    switches_frame = ttk.LabelFrame(connect_group, text="Target Switches")
    switches_frame.pack(fill=tk.X, padx=10, pady=(8, 5))
    switches_entry = scrolledtext.ScrolledText(switches_frame, height=10)
    switches_entry.pack(fill=tk.X, padx=10, pady=5)

    def open_device_file():
        path = filedialog.askopenfilename(
            title="Open device file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
            switches_entry.delete("1.0", tk.END)
            switches_entry.insert("1.0", "\n".join(lines) + ("\n" if lines else ""))
            log_info(f"Loaded {len(lines)} target(s) from {path}")
        except Exception as e:
            messagebox.showerror("Open failed", f"Could not read device file:\n{e}")
            log_error(f"Failed to open device file '{path}': {e}")


    # Toolbar under the text box
    switches_toolbar = tk.Frame(switches_frame)
    switches_toolbar.pack(fill=tk.X, padx=10, pady=(0, 5))
    ttk.Button(switches_toolbar, text="Open device file...", command=open_device_file).pack(side=tk.LEFT)

    # Ensure the Target Switches input gets focus after UI initialization
    root.after(150, lambda: switches_entry.focus_force())

    if cli_args.device:
        switches_entry.delete("1.0", tk.END)
        switches_entry.insert("1.0", cli_args.device.strip() + "\n")
    elif cli_args.device_file and os.path.isfile(cli_args.device_file):
        with open(cli_args.device_file) as f:
            switches_entry.insert("1.0", f.read())

    # Credentials
    credentials_frame = ttk.LabelFrame(connect_group, text="Credentials")
    credentials_frame.pack(fill=tk.X, padx=10, pady=5)
    username_entry = ttk.Entry(credentials_frame)
    password_entry = ttk.Entry(credentials_frame, show="*")
    tk.Label(credentials_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky='w') # Changed sticky
    username_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew') # Changed sticky
    tk.Label(credentials_frame, text="Password:").grid(row=0, column=2, padx=5, pady=5, sticky='w') # Changed sticky
    password_entry.grid(row=0, column=3, padx=5, pady=5, sticky='ew') # Changed sticky
    credentials_frame.columnconfigure(1, weight=1)
    credentials_frame.columnconfigure(3, weight=1)
    if cli_args.username:
        username_entry.insert(0, cli_args.username)
    if cli_args.password:
        password_entry.insert(0, cli_args.password)

    # Connection options
    connection_frame = ttk.LabelFrame(connect_group, text="Connection Options")
    connection_frame.pack(fill=tk.X, padx=10, pady=(5, 8))
    concurrent_spin = tk.Spinbox(connection_frame, from_=1, to=20, width=5)
    ssl_var = tk.BooleanVar(value=(cli_args.verifyssl == "true"))
    ttk.Label(connection_frame, text="Concurrent Requests:").pack(side=tk.LEFT, padx=5)
    concurrent_spin.pack(side=tk.LEFT, padx=5)
    ttk.Checkbutton(connection_frame, text="Verify SSL", variable=ssl_var).pack(side=tk.LEFT, padx=10)

    class ComboSearchOverlay:
        def __init__(self, combobox: ttk.Combobox, options, height=8):
            self.cb = combobox
            self.all = list(options)
            self.height = height
            self._filtered = self.all[:]  # start with all
            self.suppress_popup = False

            # Always use our own StringVar so we can reliably trace changes
            self.var = tk.StringVar(value=self.cb.get())
            self.cb.config(textvariable=self.var)

            # Popup (overlay) - not topmost; tie to the main window
            self.popup = tk.Toplevel(self.cb)
            self.popup.withdraw()
            self.popup.wm_overrideredirect(True)
            owner = self.cb.winfo_toplevel()
            self.popup.transient(owner)
            self.owner = owner

            # Hide the popup when the window deactivates/minimizes/moves
            owner.bind("<FocusOut>", lambda e: self.hide(), add="+")
            owner.bind("<Unmap>",    lambda e: self.hide(), add="+")
            owner.bind("<Configure>",lambda e: self.hide(), add="+")

            # Content
            frame = tk.Frame(self.popup, bd=1, relief="solid", highlightthickness=0)
            frame.pack(fill="both", expand=True)

            self.listbox = tk.Listbox(
                frame,
                height=self.height,
                activestyle="none",
                highlightthickness=0,
                bd=0,
                exportselection=False,
                selectmode=tk.SINGLE,
            )
            self.listbox.pack(fill="both", expand=True)

            # Populate
            self._set_items(self._filtered)

            # Bindings
            self.var.trace_add("write", self._on_text_change)
            self.cb.bind("<FocusIn>", self._on_focus_in, add="+")
            self.cb.bind("<FocusOut>", self._on_focus_out, add="+")
            self.cb.bind("<KeyPress>", self._on_keypress, add="+")
            self.cb.bind("<KeyRelease>", self._on_keyrelease, add="+")
            self.cb.bind("<Button-1>", self._on_click_entry, add="+")
            self.cb.bind("<<ComboboxSelected>>", lambda e: self.hide(), add="+")
            self.listbox.bind("<Button-1>", self._on_click_select, add="+")        # press: select row
            self.listbox.bind("<ButtonRelease-1>", self._on_click_accept, add="+") # release: accept row
            self.listbox.bind("<Double-Button-1>", lambda e: None, add="+")        # no-op (we accept on single click)
            self.listbox.bind("<Return>", self._accept, add="+")                   # enter: accept
            self.popup.bind("<FocusOut>", lambda e: self.hide(), add="+")

        # ---------- public ----------
        def show(self):
            if not self._filtered:
                return
            # Set rows first so Tk computes requested height
            rows = min(len(self._filtered), self.height)
            self.listbox.config(height=rows)
            self.popup.update_idletasks()

            cbx = self.cb.winfo_rootx()
            cby = self.cb.winfo_rooty()
            cbw = self.cb.winfo_width()
            cbh = self.cb.winfo_height()

            h = max(self.popup.winfo_reqheight(), 24)
            # +1 width avoids 1px "short edge" on some themes
            self.popup.geometry(f"{cbw + 1}x{h}+{cbx}+{cby + cbh}")
            self.popup.deiconify()
            self.popup.lift()
            self.cb.focus_set()  # keep typing focus

        def hide(self):
            self.popup.withdraw()
            self.suppress_popup = False

        def set_text_silently(self, value: str):
            self.suppress_popup = True
            self.var.set(value)
            self.hide()

        def bind_global_click(self, root):
            def _on_any_click(event):
                if not self.popup.winfo_viewable():
                    return
                widget = self.owner.winfo_containing(event.x_root, event.y_root)
                if widget is None:
                    self.hide()
                    return
                # Don't hide if click is on combobox or inside popup
                if widget is self.cb or str(widget).startswith(str(self.popup)):
                    return
                self.hide()
            root.bind_all("<Button-1>", _on_any_click, add="+")

        # ---------- internals ----------
        def _set_items(self, items):
            self.listbox.delete(0, tk.END)
            for it in items:
                self.listbox.insert(tk.END, it)
            if items:
                self.listbox.selection_clear(0, tk.END)
                self.listbox.activate(0)
                self.listbox.selection_set(0)

        def _filter_items(self, text):
            lt = text.lower()
            return self.all if not lt else [v for v in self.all if lt in v.lower()]

        def _on_text_change(self, *_):
            text = self.var.get()
            self._filtered = self._filter_items(text)
            self._set_items(self._filtered)
            if self._filtered and not self.suppress_popup:
                self.show()
            else:
                self.hide()

        def _on_focus_in(self, _):
            self._on_text_change()

        def _on_focus_out(self, _):
            # If focus leaves both, hide shortly after
            def _safe_hide():
                try:
                    focused = self.popup.focus_get()
                except (tk.TclError, KeyError):
                    focused = None
                if not focused:
                    self.hide()
            self.cb.after(100, _safe_hide)

        def _on_click_entry(self, _):
            # Show dropdown on click; do not auto-accept
            self._on_text_change()

        def _accept(self, _event=None):
            sel = self.listbox.curselection()
            if sel:
                value = self.listbox.get(sel[0])
                self.var.set(value)
                self.cb.event_generate("<<ComboboxSelected>>")
            self.hide()
            self.cb.icursor(tk.END)
            self.cb.focus_set()

        def _on_keypress(self, e):
            # Navigate list while keeping focus in entry
            if not self.popup.winfo_viewable():
                return
            if e.keysym in ("Down", "Up"):
                n = self.listbox.size()
                if n == 0:
                    return "break"
                cur = self.listbox.curselection()
                i = cur[0] if cur else -1
                i = (i + 1) if e.keysym == "Down" else (i - 1)
                i = max(0, min(n - 1, i))
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(i)
                self.listbox.activate(i)
                self.listbox.see(i)
                return "break"
            if e.keysym == "Return":
                self._accept()
                return "break"
            if e.keysym == "Escape":
                self.hide()
                return "break"

        def _on_keyrelease(self, _):
            # Keep overlay synced after special keys
            if self.popup.winfo_viewable():
                self.cb.after_idle(self._on_text_change)

        def _on_click_select(self, e):
            # Select the row under the pointer on mouse down
            i = self.listbox.nearest(e.y)
            if 0 <= i < self.listbox.size():
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(i)
                self.listbox.activate(i)
                self.listbox.see(i)
            # don't accept yet

        def _on_click_accept(self, e):
            # Only accept if the release is still over the list (prevents stray accepts)
            x, y = e.x, e.y
            if 0 <= x < self.listbox.winfo_width() and 0 <= y < self.listbox.winfo_height():
                self._accept()


    def attach_search_dropdown(combobox: ttk.Combobox, options, height=8):
        return ComboSearchOverlay(combobox, options, height=height)

    # Request tabs (Saved vs Custom)
    request_tabs = ttk.Notebook(data_group)
    request_tabs.pack(fill=tk.X, padx=10, pady=(8, 5))
    saved_tab = ttk.Frame(request_tabs)
    custom_tab = ttk.Frame(request_tabs)
    request_tabs.add(saved_tab, text="Saved Requests")
    request_tabs.add(custom_tab, text="Custom Request")

    # Custom Request
    custom_frame = ttk.LabelFrame(custom_tab, text="Custom Request")
    custom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # API Options
    api_frame = ttk.LabelFrame(custom_frame, text="API Options")
    api_frame.pack(fill=tk.X, padx=10, pady=5)
    # --- widgets ---
    endpoint_combobox = ttk.Combobox(api_frame, values=api_endpoints, state="normal")
    endpoint_combobox.current(0)
    endpoint_overlay = attach_search_dropdown(endpoint_combobox, api_endpoints, height=8)
    if "/system" in api_endpoints:
        endpoint_combobox.current(api_endpoints.index("/system"))
    else:
        endpoint_combobox.set("/system")
    version_value = tk.StringVar(value="10.04")
    version_entry = ttk.Combobox(
        api_frame, textvariable=version_value,
        values=["10.04","10.08","10.09","10.11","10.12","10.13","10.14","10.15"],
        width=6
    )
    version_entry.current(0)
    depth_entry = ttk.Spinbox(api_frame, from_=1, to=10, width=4)
    selector_value = tk.StringVar(value="")
    selector_combobox = ttk.Combobox(
        api_frame, textvariable=selector_value,
        values=["configuration","status","statistics"],
        state="readonly"
    )
    attributes_entry = ttk.Entry(api_frame)
    attributes_autofilled = [False]
    # --- grid (Endpoint full row; small controls on next row) ---
    # Give Endpoint (col 1) and Selector (col 5) and Attributes (col 1) room to stretch
    api_frame.grid_columnconfigure(1, weight=1)  # Endpoint / Attributes grow
    api_frame.grid_columnconfigure(5, weight=1)  # Selector grows (optional)
    # Row 0: Endpoint
    ttk.Label(api_frame, text="Endpoint:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    endpoint_combobox.grid(row=0, column=1, columnspan=5, padx=5, pady=5, sticky="ew")
    # Row 1: Version / Depth / Selector
    ttk.Label(api_frame, text="Version:").grid(row=1, column=0, padx=5, pady=2, sticky="e")
    version_entry.grid(row=1, column=1, padx=5, pady=2, sticky="w")
    ttk.Label(api_frame, text="Depth:").grid(row=1, column=2, padx=5, pady=2, sticky="e")
    depth_entry.grid(row=1, column=3, padx=5, pady=2, sticky="w")
    ttk.Label(api_frame, text="Selector:").grid(row=1, column=4, padx=5, pady=2, sticky="e")
    selector_combobox.grid(row=1, column=5, padx=5, pady=2, sticky="ew")
    # Row 2: Attributes (full width)
    ttk.Label(api_frame, text="Filter Attributes:").grid(row=2, column=0, sticky="ne", padx=(8,4), pady=(4,6))
    attributes_entry.grid(row=2, column=1, columnspan=5, sticky="ew", padx=(0,12), pady=(4,6))
    # Pre-fill attributes if provided
    if cli_args.attributes:
        attributes_entry.insert(0, cli_args.attributes)

    def on_attributes_edit(_event=None):
        attributes_autofilled[0] = False
    attributes_entry.bind("<KeyRelease>", on_attributes_edit, add="+")

    def update_endpoint_dependent_fields(_event=None):
        ep = endpoint_combobox.get().strip()
        if not ep:
            return
        key = ep if ep.startswith("/") else f"/{ep}"
        meta = endpoint_meta.get(key)

        if meta:
            selector_values = meta.get("selector_values", []) or []
            if meta.get("has_selector") and selector_values:
                values = [""] + [v for v in selector_values if v]
                selector_combobox.config(state="readonly", values=values)
                if selector_value.get() not in selector_values:
                    selector_value.set("")
            else:
                selector_combobox.set("")
                selector_combobox.config(state="disabled", values=[])

            attr_values = meta.get("attributes_values", []) or []
            if attr_values and (not attributes_entry.get().strip() or attributes_autofilled[0]):
                attributes_entry.delete(0, tk.END)
                attributes_entry.insert(0, ",".join(attr_values))
                attributes_autofilled[0] = True
            elif not attr_values and attributes_autofilled[0]:
                attributes_entry.delete(0, tk.END)
                attributes_autofilled[0] = False
        else:
            # Fallback: enable selector only for known prefixes
            endpoint_norm = ep.lstrip("/")
            supports_selector = any(endpoint_norm.startswith(p) for p in [
                "system/interfaces", "system/vlans", "system/subsystems", "system/acls"
            ])
            if supports_selector:
                values = ["", "configuration", "status", "statistics"]
                selector_combobox.config(state="readonly", values=values)
                if selector_value.get() not in values:
                    selector_value.set("")
            else:
                selector_combobox.set("")
                selector_combobox.config(state="disabled", values=[])
            if attributes_autofilled[0]:
                attributes_entry.delete(0, tk.END)
                attributes_autofilled[0] = False

    endpoint_combobox.bind("<<ComboboxSelected>>", update_endpoint_dependent_fields, add="+")
    endpoint_combobox.bind("<FocusOut>", update_endpoint_dependent_fields, add="+")
    update_endpoint_dependent_fields()

    # Saved Requests
    saved_requests_frame = ttk.LabelFrame(saved_tab, text="Saved Requests")
    saved_requests_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    saved_requests = load_saved_requests()
    saved_list_frame = ttk.Frame(saved_requests_frame)
    saved_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    saved_listbox = tk.Listbox(saved_list_frame, activestyle="none", exportselection=False)
    saved_scroll = ttk.Scrollbar(saved_list_frame, orient="vertical", command=saved_listbox.yview)
    saved_listbox.config(yscrollcommand=saved_scroll.set)
    saved_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    saved_scroll.pack(side=tk.RIGHT, fill=tk.Y)


    def refresh_saved_combo():
        def build_url(r):
            endpoint = r.get("endpoint", "")
            version = r.get("version", "")
            depth = r.get("depth", "")
            selector = r.get("selector", "")
            attributes = r.get("attributes", "")
            ep = endpoint if str(endpoint).startswith("/") else f"/{endpoint}" if endpoint else ""
            params = []
            if depth:
                params.append(f"depth={depth}")
            if selector:
                params.append(f"selector={selector}")
            if attributes:
                params.append(f"attributes={attributes}")
            url = f"/rest/v{version}{ep}"
            if params:
                url += "?" + "&".join(params)
            return url

        saved_requests.sort(key=lambda r: str(r.get("name", "")).lower())
        saved_listbox.delete(0, tk.END)
        for r in saved_requests:
            name = r.get("name", "Unnamed")
            saved_listbox.insert(tk.END, name)

        if saved_requests:
            saved_listbox.selection_clear(0, tk.END)
            saved_listbox.selection_set(0)
            saved_listbox.activate(0)
        # no URL preview; list only

    def apply_saved_request(idx: int):
        if idx < 0 or idx >= len(saved_requests):
            return
        r = saved_requests[idx]
        endpoint_overlay.set_text_silently(r.get("endpoint", ""))
        update_endpoint_dependent_fields()

        version_value.set(r.get("version", version_value.get()))
        depth_entry.delete(0, tk.END)
        depth_entry.insert(0, str(r.get("depth", "1")))

        selector_value.set(r.get("selector", "") or "")

        attributes_entry.delete(0, tk.END)
        attributes_entry.insert(0, r.get("attributes", "") or "")
        attributes_autofilled[0] = False

        concurrent_spin.delete(0, tk.END)
        concurrent_spin.insert(0, str(r.get("concurrency", 5)))

    def on_saved_selected(_event=None):
        sel = saved_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        apply_saved_request(idx)

    def save_current_request():
        name = simpledialog.askstring("Save Request", "Name for this request:")
        if not name:
            return
        name = name.strip()
        if not name:
            return

        req = {
            "name": name,
            "endpoint": endpoint_combobox.get().strip(),
            "version": version_value.get().strip(),
            "depth": depth_entry.get().strip() or "1",
            "selector": selector_value.get().strip(),
            "attributes": attributes_entry.get().strip(),
            "verifyssl": bool(ssl_var.get()),
            "concurrency": int(concurrent_spin.get() or 5),
        }

        # Overwrite if name exists
        for i, existing in enumerate(saved_requests):
            if existing.get("name") == name:
                saved_requests[i] = req
                break
        else:
            saved_requests.append(req)

        try:
            save_saved_requests(saved_requests)
            refresh_saved_combo()
        except Exception as e:
            messagebox.showerror("Save failed", f"Could not save request:\n{e}")

    def delete_saved_request_by_index(idx: int):
        if idx < 0 or idx >= len(saved_requests):
            return
        name = saved_requests[idx].get("name", "Unnamed")
        if not messagebox.askyesno("Delete Request", f"Delete saved request '{name}'?"):
            return
        saved_requests.pop(idx)
        try:
            save_saved_requests(saved_requests)
            refresh_saved_combo()
        except Exception as e:
            messagebox.showerror("Delete failed", f"Could not save changes:\n{e}")

    def on_saved_right_click(event):
        idx = saved_listbox.nearest(event.y)
        if idx < 0 or idx >= len(saved_requests):
            return
        saved_listbox.selection_clear(0, tk.END)
        saved_listbox.selection_set(idx)
        menu = tk.Menu(saved_listbox, tearoff=0)
        menu.add_command(label="Delete Saved Request", command=lambda: delete_saved_request_by_index(idx))
        menu.post(event.x_root, event.y_root)

    saved_listbox.bind("<<ListboxSelect>>", on_saved_selected, add="+")
    saved_listbox.bind("<Button-3>", on_saved_right_click, add="+")

    # Delete button (explicit action)
    saved_actions = ttk.Frame(saved_requests_frame)
    saved_actions.pack(fill=tk.X, padx=10, pady=(0, 6))
    ttk.Button(saved_actions, text="Delete Saved Request", style="SecondaryAction.TButton",
               command=lambda: delete_saved_request_by_index(
                   saved_listbox.curselection()[0] if saved_listbox.curselection() else -1
               )).pack(side=tk.LEFT)
    refresh_saved_combo()
    endpoint_overlay.bind_global_click(root)

    # Show the default tab first (Saved Requests)
    request_tabs.select(saved_tab)


    if cli_args.endpoint:
        endpoint_combobox.set(cli_args.endpoint)
    if cli_args.version:
        version_value.set(cli_args.version)
    if cli_args.depth is not None:
        depth_entry.delete(0, tk.END)
        depth_entry.insert(0, str(cli_args.depth))
    if cli_args.selector:
        selector_value.set(cli_args.selector)
    if cli_args.concurrency:
        concurrent_spin.delete(0, tk.END)
        concurrent_spin.insert(0, str(cli_args.concurrency))



    # Save current custom request
    custom_actions = ttk.Frame(custom_frame)
    custom_actions.pack(fill=tk.X, padx=10, pady=(0, 6))
    ttk.Button(custom_actions, text="Save Current Request", command=save_current_request).pack(side=tk.LEFT)

    # Recent Requests
    recent_frame = ttk.LabelFrame(custom_frame, text="Recent Requests")
    recent_frame.pack(fill=tk.X, padx=10, pady=5)
    recent_combo = ttk.Combobox(recent_frame, state="readonly")
    recent_combo.pack(fill=tk.X, padx=10, pady=5)
    def on_recent_selected(event):
        index = recent_combo.current()
        if index == -1: return
        config = recent_calls[index]
        endpoint_combobox.set(config["endpoint"])
        version_value.set(config["version"])
        depth_entry.delete(0, tk.END)
        depth_entry.insert(0, config["depth"])
        selector_combobox.set(config["selector"])

    recent_combo.bind("<<ComboboxSelected>>", on_recent_selected)

    # Generate CLI button
    ttk.Button(controls_frame, text="Generate CLI...", style="SecondaryAction.TButton", command=lambda: open_cli_builder_popup(
        root,
        username_entry, password_entry, switches_entry,
        endpoint_combobox, version_value, depth_entry,
        selector_value, ssl_var, concurrent_spin, attributes_entry
    )).pack(anchor="w", padx=10, pady=(0, 8))


    # Run/Stop Button functionality
    def toggle_run_stop():
        if run_button_ref.cget("text") == "Run API Requests":
            start_api_calls()
        else:
            stop_api_calls()

    def start_api_calls(append=False, switches_override=None):
        stop_event.clear() # Clear the stop event for a new run
        run_button_ref.config(text="Stop API Requests", style="RunDanger.TButton", command=toggle_run_stop, width=RUN_BUTTON_WIDTH) # Change button to Stop
        
        # Decide which switches to run
        switches = switches_override
        if switches is None:
            switches = [line.strip() for line in switches_entry.get("1.0", "end").splitlines() if line.strip()]

        username = username_entry.get()
        password = password_entry.get()
        endpoint = endpoint_combobox.get()
        version = version_value.get()
        depth = depth_entry.get()
        selector = selector_value.get()
        attributes = attributes_entry.get().strip()
        verify_ssl = ssl_var.get()
        concurrency = int(concurrent_spin.get())

        if not append:
            failed_switches.clear()
            stat_success_var.set("0")
            stat_fail_var.set("0")
            stat_total_var.set(str(len(switches)))
            retry_btn.config(state="disabled")

            all_json_results.clear()
            tree.delete(*tree.get_children())
            raw_text.delete("1.0", tk.END)
            log_text.delete("1.0", tk.END)

        def on_result(switch, data, hostname):
            # This function is called from the worker thread, so GUI updates must use root.after()
            root.after(0, lambda: _update_gui_with_result(switch, data, hostname))

        def _update_gui_with_result(switch, data, hostname):
            title = f"{hostname}: {switch} - {endpoint_combobox.get()}"

            # Normalize non-dict results to avoid crashing on list responses
            if isinstance(data, dict):
                data["__title__"] = title
            else:
                data = {"__title__": title, "result": data}
            all_json_results.append(data)

            # When appending (retry), we want: successes decrease Fail and increase Success.
            # When fresh run, we just count normally.
            is_failure = isinstance(data, dict) and "error" in data

            if is_failure:
                # Count failure
                stat_fail_var.set(str(int(stat_fail_var.get()) + 1 if not append else int(stat_fail_var.get())))
                # In append mode, a failure remains a failure; keep it in the new failed list we'll rebuild below
                top = tree.insert("", "end", text=title, values=(data.get('error', 'Unknown error'),))
            else:
                # Count success
                if append:
                    # This success is converting a previous failure -> decrement Fail, increment Success
                    try:
                        stat_fail_var.set(str(max(0, int(stat_fail_var.get()) - 1)))
                    except Exception:
                        pass
                    try:
                        stat_success_var.set(str(int(stat_success_var.get()) + 1))
                    except Exception:
                        stat_success_var.set("1")
                else:
                    # Normal fresh run
                    try:
                        stat_success_var.set(str(int(stat_success_var.get()) + 1))
                    except Exception:
                        stat_success_var.set("1")

                top = tree.insert("", "end", text=title, open=False)
                insert_json_tree(tree, top, data)

            # Raw pane (truncate very large payloads to avoid UI freezes)
            raw_payload = json.dumps(data, indent=2)
            if len(raw_payload) > RAW_MAX_CHARS:
                raw_payload = (
                    raw_payload[:RAW_MAX_CHARS]
                    + "\n\n[truncated output; increase RAW_MAX_CHARS to show more]\n"
                )
            raw_text.insert(tk.END, f"{title}\n{raw_payload}\n\n")
            raw_text.see(tk.END)

            # Track failures for future retries: rebuild failed_switches incrementally
            # In fresh run -> we're building the first failure list
            # In append mode -> we're replacing the old list with the *still* failing set
            if append:
                # On append we rebuild from what's left: remove successes from the previous list,
                # and keep failed ones in a new list
                if not is_failure:
                    # If this IP was in the previous failure list, remove it
                    try:
                        if switch in failed_switches:
                            failed_switches.remove(switch)
                    except Exception:
                        pass
                else:
                    if switch not in failed_switches:
                        failed_switches.append(switch)
            else:
                # Fresh run: collect failures as they happen
                if is_failure and switch not in failed_switches:
                    failed_switches.append(switch)


        def on_progress_update(done, total): # Renamed to avoid conflict with `on_progress` in run_api_calls
            # This function is called from the worker thread, so GUI updates must use root.after()
            root.after(0, lambda: progress_var.set(f"Progress: {done}/{total} switches complete"))
            root.after(0, root.update_idletasks) # Force GUI update

        progress_var.set("Retrying failed switches..." if append else "Running API calls...")
        root.update_idletasks()

        # Run API calls in a separate thread to keep GUI responsive
        threading.Thread(target=lambda: run_api_calls_threaded(
            switches, username, password, endpoint, version, depth, selector, verify_ssl,
            on_result, on_progress_update, concurrency, attributes
        )).start()

        recent_calls.insert(0, {
            "endpoint": endpoint,
            "version": version,
            "depth": depth,
            "selector": selector,
            "attributes": attributes
        })
        recent_calls[:] = recent_calls[:10]  # limit to 10 entries
        recent_combo["values"] = [
            (
                f"/rest/v{r['version']}"
                f"{(r['endpoint'] if str(r['endpoint']).startswith('/') else '/' + str(r['endpoint']))}"
                + (
                    ""
                    if not any([r.get('depth'), r.get('selector'), r.get('attributes')])
                    else "?"
                    + "&".join(
                        p for p in [
                            f"depth={r['depth']}" if r.get("depth") else "",
                            f"selector={r['selector']}" if r.get("selector") else "",
                            f"attributes={r.get('attributes','')}" if r.get("attributes") else "",
                        ] if p
                    )
                )
            )
            for r in recent_calls
        ]
        if recent_calls:
            recent_combo.current(0)

    def stop_api_calls():
        stop_event.set() # Set the stop event
        log_info("Stopping API calls...") # Log the action
        progress_var.set("Stopping API calls...") # Update progress label
        # The button state will be reset in run_api_calls_threaded when it finishes/stops
        # Change button state to gray and disabled
        run_button_ref.config(text="Stopping...", style="RunDanger.TButton", state="disabled", width=RUN_BUTTON_WIDTH)

    def run_api_calls_threaded(switches, username, password, endpoint, version, depth, selector, verify_ssl,
                               on_result_callback, on_progress_callback, concurrency, attributes):
        run_api_calls(
            switches=switches,
            username=username,
            password=password,
            endpoint=endpoint,
            version=version,
            depth=depth,
            selector=selector,
            verify_ssl=verify_ssl,
            on_result=on_result_callback,
            on_progress=on_progress_callback,
            stop_event=stop_event, # Pass the stop event
            concurrency=concurrency,
            attributes=attributes
        )
        # Reset button state and progress label after calls are complete or stopped
        def _finish_ui():
            run_button_ref.config(text="Run API Requests", style="PrimaryAction.TButton", state="normal", command=toggle_run_stop, width=RUN_BUTTON_WIDTH)

            succ = int(stat_success_var.get())
            fail = int(stat_fail_var.get())
            totl = int(stat_total_var.get()) if stat_total_var.get().isdigit() else succ + fail

            if stop_event.is_set():
                progress_var.set(f"API calls stopped.")
            else:
                progress_var.set(f"API calls complete.")

            log_info(f"Run summary - Success: {succ}, Failed: {fail}, Total: {totl}")

            # Enable Retry button if any failures
            retry_btn.config(state=("normal" if fail > 0 else "disabled"))

        root.after(100, _finish_ui)


    run_button_ref = make_run_button(controls_frame, toggle_run_stop) # Assign to global reference
    run_button_ref.pack(fill=tk.X, padx=10, pady=6)

    # Stats and Retry
    stats_frame = ttk.LabelFrame(controls_frame, text="Run Summary")
    stats_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

    ttk.Label(stats_frame, text="Success:").grid(row=0, column=0, padx=(8,2), pady=5, sticky="w")
    ttk.Label(stats_frame, textvariable=stat_success_var).grid(row=0, column=1, padx=(0,8), pady=5, sticky="w")

    ttk.Label(stats_frame, text="Failed:").grid(row=0, column=2, padx=(8,2), pady=5, sticky="w")
    ttk.Label(stats_frame, textvariable=stat_fail_var).grid(row=0, column=3, padx=(0,8), pady=5, sticky="w")

    ttk.Label(stats_frame, text="Total:").grid(row=0, column=4, padx=(8,2), pady=5, sticky="w")
    ttk.Label(stats_frame, textvariable=stat_total_var).grid(row=0, column=5, padx=(0,8), pady=5, sticky="w")

    def _remove_prior_results_for_switch(switch_ip, endpoint_text=None):
        """Remove prior rows for a given switch (and optional endpoint) from the tree
        and from all_json_results so we don't duplicate on retry append."""
        # 1) Remove from Tree
        for iid in tree.get_children(""):
            title = tree.item(iid, "text") or ""
            # Match "...: <IP> - <endpoint>"
            has_ip = f": {switch_ip} -" in title
            has_ep = (endpoint_text is None) or title.endswith(f" - {endpoint_text}")
            if has_ip and has_ep:
                tree.delete(iid)

        # 2) Remove from backing results list so filters/exports don't re-add
        i = len(all_json_results) - 1
        while i >= 0:
            r = all_json_results[i]
            if isinstance(r, dict):
                t = r.get("__title__", "")
                has_ip = f": {switch_ip} -" in t
                has_ep = (endpoint_text is None) or t.endswith(f" - {endpoint_text}")
                if has_ip and has_ep:
                    all_json_results.pop(i)
            i -= 1

    def retry_failed():
        if not failed_switches:
            return
        targets = list(failed_switches)  # snapshot; this list will change as results arrive
        current_endpoint = endpoint_combobox.get().strip()

        # Remove prior failed entries for those IPs (tree + results list)
        for ip in targets:
            _remove_prior_results_for_switch(ip, current_endpoint)

        # Now append fresh results inline (no clearing)
        start_api_calls(append=True, switches_override=targets)

    retry_btn = ttk.Button(stats_frame, text="Retry Failed", command=retry_failed, state="disabled")
    retry_btn.grid(row=1, column=0, columnspan=6, padx=8, pady=(0, 8), sticky="ew")

    # Help button now in header (top-right)
    # Progress label setup
    progress_var = tk.StringVar(value="Ready") # Initial text for progress
    progress_label = tk.Label(root, textvariable=progress_var, anchor="w")
    progress_label.pack(fill=tk.X, padx=10, pady=(0, 5))


    # Tabbed Interface for Tree, Raw JSON, and Logs
    tree_tab = ttk.Frame(tab_control)
    raw_tab = ttk.Frame(tab_control)
    log_tab = ttk.Frame(tab_control) # New log tab
    tab_control.add(tree_tab, text="JSON Viewer")
    tab_control.add(raw_tab, text="Raw Response")
    tab_control.add(log_tab, text="Logs") # Add log tab

    # Tree View Tab
    filter_frame = tk.Frame(tree_tab)
    filter_frame.pack(fill=tk.X, padx=5, pady=2)
    tk.Button(filter_frame, text="Apply", command=lambda: apply_filter(filter_entry.get(), all_json_results, tree)).pack(side=tk.LEFT, padx=5)
    tk.Button(filter_frame, text="Clear", command=lambda: [filter_entry.delete(0, tk.END), apply_filter("", all_json_results, tree)]).pack(side=tk.LEFT, padx=5)
    tk.Label(filter_frame, text="Filter JSON:").pack(side=tk.LEFT)
    filter_entry = tk.Entry(filter_frame)
    filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    ttk.Button(filter_frame, text="Export Filtered to CSV", command=lambda: export_tree_to_csv_from_tree(tree)).pack(pady=5)
    tree_frame = ttk.Frame(tree_tab)
    tree_frame.pack(fill=tk.BOTH, expand=True)

    tree_scrollbar = ttk.Scrollbar(tree_frame)
    tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    tree = ttk.Treeview(tree_frame, columns=("value",), show="tree headings", yscrollcommand=tree_scrollbar.set)
    tree.heading("#0", text="Key")
    tree.heading("value", text="Value")
    tree.column("value", width=300)

    tree.pack(fill=tk.BOTH, expand=True)
    tree_scrollbar.config(command=tree.yview)
    

    # Raw View Tab
    search_frame = tk.Frame(raw_tab)
    search_frame.pack(fill=tk.X, padx=5, pady=5)

    tk.Button(search_frame, text="Previous", command=lambda: prev_match(raw_text, search_matches, search_current_index)).pack(side=tk.LEFT)
    tk.Button(search_frame, text="Next", command=lambda: next_match(raw_text, search_matches, search_current_index)).pack(side=tk.LEFT)
    tk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(10, 0))
    raw_search_entry = tk.Entry(search_frame)
    raw_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
    raw_match_label = tk.Label(search_frame, text="Matches: 0")
    raw_match_label.pack(side=tk.LEFT, padx=5)
    raw_text = scrolledtext.ScrolledText(raw_tab, height=10)
    raw_text.pack(fill=tk.BOTH, expand=True)

    bind_search_keys(raw_search_entry, lambda term: search_raw_view(term, raw_text, raw_match_label, search_matches, search_current_index))

    # Pass additional arguments to on_tree_right_click
    tree.bind("<Button-3>", lambda e: on_tree_right_click(e, tree, filter_entry, endpoint_combobox, version_value, depth_entry, run_button_ref, attributes_entry))

    raw_text.bind("<Button-3>", lambda e: on_raw_right_click(
        e, raw_text, raw_search_entry, raw_match_label, search_matches, search_current_index))
    
    # Log Tab content
    log_text = scrolledtext.ScrolledText(log_tab, height=10, state='disabled') #
    log_text.pack(fill=tk.BOTH, expand=True) #
    configure_logger(log_text) # Configure the logger to send output to this widget

    footer = tk.Label(root, text=f"MultiSwitchCXplorer v{APP_VERSION} | (c) gregory.damron@hpe.com", font=("Arial", 7), anchor="e") # Use APP_VERSION
    footer.pack(fill=tk.X, side=tk.BOTTOM, anchor="e", padx=5, pady=(0, 2))


    root.mainloop()
