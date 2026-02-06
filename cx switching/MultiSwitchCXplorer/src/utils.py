from datetime import datetime
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import Menu, filedialog, messagebox
import csv


# Global reference for the log text widget
_log_text_widget = None

def configure_logger(text_widget):
    global _log_text_widget
    _log_text_widget = text_widget

def _insert_log_message(message, level):
    if _log_text_widget:
        _log_text_widget.config(state='normal')
        _log_text_widget.insert(tk.END, f"[{level} {datetime.now().strftime('%H:%M:%S')}] {message}\n")
        _log_text_widget.see(tk.END)
        _log_text_widget.config(state='disabled')
    print(f"[{level} {datetime.now().strftime('%H:%M:%S')}] {message}")

def log_info(message):
    _insert_log_message(message, "INFO")

def log_error(message):
    _insert_log_message(message, "ERROR")

def bind_search_keys(entry_widget, callback):
    entry_widget.bind("<Return>", lambda event: callback(entry_widget.get()))
    entry_widget.bind("<KeyRelease>", lambda event: callback(entry_widget.get()))

def bind_selector_toggle(endpoint_combobox, selector_combobox):
    def check_selector_state(event=None):
        endpoint = endpoint_combobox.get().lstrip("/")
        supports_selector = any(endpoint.startswith(p) for p in [
            "system/interfaces", "system/vlans", "system/subsystems", "system/acls"
        ])
        if supports_selector:
            selector_combobox.config(state="readonly")
        else:
            selector_combobox.set("")
            selector_combobox.config(state="disabled")
    endpoint_combobox.bind("<<ComboboxSelected>>", check_selector_state)
    endpoint_combobox.bind("<FocusOut>", check_selector_state)
    check_selector_state()

def search_raw_view(term, raw_text, raw_match_label, search_matches_ref, search_current_index_ref):
    search_matches_ref.clear()
    search_current_index_ref[0] = 0
    raw_text.tag_remove("search_match", "1.0", tk.END)
    raw_text.tag_remove("current_match", "1.0", tk.END)

    if not term:
        raw_match_label.config(text="Matches: 0")
        return

    exact = term.startswith('"') and term.endswith('"')
    if exact:
        term = term.strip('"')

    start_index = "1.0"
    while True:
        start_index = raw_text.search(term, start_index, stopindex=tk.END, nocase=True)
        if not start_index:
            break
        end_index = f"{start_index}+{len(term)}c"
        match_text = raw_text.get(start_index, end_index)

        if exact and match_text.lower() != term.lower():
            start_index = end_index
            continue

        search_matches_ref.append((start_index, end_index))
        raw_text.tag_add("search_match", start_index, end_index)
        start_index = end_index

    raw_text.tag_config("search_match", background="yellow")
    raw_text.tag_config("current_match", background="orange")

    if search_matches_ref:
        highlight_current_match(raw_text, search_matches_ref, search_current_index_ref[0])
        raw_match_label.config(text=f"Matches: {len(search_matches_ref)}")
    else:
        raw_match_label.config(text="Matches: 0")

def highlight_current_match(raw_text, search_matches, index):
    raw_text.tag_remove("current_match", "1.0", tk.END)
    if not search_matches:
        return
    start_index, end_index = search_matches[index]
    raw_text.tag_add("current_match", start_index, end_index)
    raw_text.see(start_index)

def next_match(raw_text, search_matches, search_current_index_ref):
    if not search_matches:
        return
    search_current_index_ref[0] = (search_current_index_ref[0] + 1) % len(search_matches)
    highlight_current_match(raw_text, search_matches, search_current_index_ref[0])

def prev_match(raw_text, search_matches, search_current_index_ref):
    if not search_matches:
        return
    search_current_index_ref[0] = (search_current_index_ref[0] - 1) % len(search_matches)
    highlight_current_match(raw_text, search_matches, search_current_index_ref[0])

def insert_json_tree(tree, parent, json_data, term=None, open=False, flat_display=False):
    """
    Builds or filters a TreeView depending on the presence of `term`.
    """
    def has_match(data):
        if isinstance(data, dict):
            return any((term == str(k).lower() if is_exact else term in str(k).lower()) or has_match(v) for k, v in data.items())
        elif isinstance(data, list):
            return any(has_match(i) for i in data)
        else:
            return term == str(data).lower() if is_exact else term in str(data).lower()

    def recurse(parent_id, data):
        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k != '__title__'}
            if not data:
                tree.insert(parent_id, 'end', text="(empty object)")
                return
            for k, v in data.items():
                if term:
                    match_key = term == str(k).lower() if is_exact else term in str(k).lower()
                    match_value = has_match(v)
                    if not (match_key or match_value):
                        continue
                    node = tree.insert(parent_id, 'end', text=f"{k}", values=(v if not isinstance(v, (dict, list)) else "",), open=open)
                    # Always recurse if key matched, even with exact match
                    if isinstance(v, (dict, list)) or match_key:
                        recurse(node, v)
                else:
                    node = tree.insert(parent_id, 'end', text=f"{k}", values=(v if not isinstance(v, (dict, list)) else "",), open=open)
                    if isinstance(v, (dict, list)):
                        recurse(node, v)
        elif isinstance(data, list):
            if not data:
                tree.insert(parent_id, 'end', text="(empty list)")
                return
            for i, item in enumerate(data):
                if term and not has_match(item):
                    continue
                node = tree.insert(parent_id, 'end', text=f"Item {i}", open=open)
                recurse(node, item)

    if term:
        term = term.lower()
        is_exact = term.startswith('"') and term.endswith('"')
        if is_exact:
            term = term.strip('"')

    recurse(parent, json_data)

def apply_filter(term, all_json_results, tree):
    tree.delete(*tree.get_children())
    if not term:
        for result in all_json_results:
            title = result.get("__title__", "Switch Result")
            top = tree.insert('', 'end', text=title, open=False)
            insert_json_tree(tree, top, result, open=False)
        return

    for result in all_json_results:
        title = result.get("__title__", "Switch Result")
        top = tree.insert('', 'end', text=title, open=True)
        insert_json_tree(tree, top, result, term=term, open=True)

def on_tree_right_click(
    event,
    tree,
    filter_entry,
    endpoint_combobox,
    version_value_tkvar,
    depth_entry_widget,
    run_button_widget,
    attributes_entry  # <-- NEW: pass your attributes Entry here
):
    region = tree.identify("region", event.x, event.y)
    iid = tree.identify_row(event.y)
    column = tree.identify_column(event.x)
    if not iid:
        return

    item = tree.item(iid)
    value = item['values'][0] if item['values'] else ""
    key = item['text']

    menu = tk.Menu(tree, tearoff=0)
    if column == "#1":  # right-clicked in value column
        menu.add_command(label="Copy Value", command=lambda: tree.clipboard_append(value))
        if value.startswith("/rest/"):
            menu.add_separator()

            def populate_api_fields():
                try:
                    rest = value.split("/rest/")[1]
                    version, endpoint = rest.split("/", 1)
                    endpoint_combobox.set(endpoint)
                    filter_entry.delete(0, tk.END)
                    filter_entry.insert(0, "")  # Clear filter entry
                    version_value_tkvar.set(version.lstrip('v'))
                    depth_entry_widget.delete(0, tk.END)
                    depth_entry_widget.insert(0, "1")
                    messagebox.showinfo("Action", f"API endpoint {endpoint} (version {version}) fields populated.")
                except Exception as e:
                    log_error(f"Error populating API fields from right-click: {e}")

            menu.add_command(label="Populate API Fields", command=populate_api_fields)

            def populate_api_fields_and_run():
                try:
                    rest = value.split("/rest/")[1]
                    version, endpoint = rest.split("/", 1)
                    endpoint_combobox.set(endpoint)
                    filter_entry.delete(0, tk.END)
                    filter_entry.insert(0, "")
                    version_value_tkvar.set(version.lstrip('v'))
                    depth_entry_widget.delete(0, tk.END)
                    depth_entry_widget.insert(0, "1")
                    run_button_widget.invoke()
                except Exception as e:
                    log_error(f"Error preparing API fields from right-click: {e}")

            menu.add_command(label="Populate Fields & Run API", command=populate_api_fields_and_run)

    else:
        menu.add_command(label="Copy Key", command=lambda: tree.clipboard_append(key))

        # REPLACEMENT FOR "Filter by" -> "Add to attributes"
        def add_to_attributes():
            try:
                current = attributes_entry.get().strip()
                if current:
                    # Append with a single comma (no extra spaces)
                    if current.endswith(","):
                        new_value = current + key
                    else:
                        new_value = current + "," + key
                else:
                    new_value = key

                attributes_entry.delete(0, tk.END)
                attributes_entry.insert(0, new_value)
            except Exception as e:
                log_error(f"Error adding key to attributes: {e}")

        menu.add_command(label="Add to attributes", command=add_to_attributes)

    menu.post(event.x_root, event.y_root)
def on_raw_right_click(event, raw_text, raw_search_entry, raw_match_label, search_matches, search_current_index):
    try:
        selected = raw_text.get(tk.SEL_FIRST, tk.SEL_LAST)
    except tk.TclError:
        return

    menu = Menu(raw_text, tearoff=0)
    menu.add_command(label="Copy", command=lambda: raw_text.clipboard_append(selected))
    menu.add_command(label="Search by", command=lambda: [raw_search_entry.delete(0, tk.END), raw_search_entry.insert(0, selected), search_raw_view(selected, raw_text, raw_match_label, search_matches, search_current_index)])
    menu.post(event.x_root, event.y_root)

def export_tree_to_csv_from_tree(tree):
    filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not filepath:
        return

    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Hostname", "IP/FQDN", "API Endpoint", "Key Path", "Value"])

        def walk_tree(item_id, parent_path=[]):
            key = tree.item(item_id, "text")
            value = tree.item(item_id, "values")
            children = tree.get_children(item_id)

            current_path = parent_path + [key]

            if children:
                for child_id in children:
                    yield from walk_tree(child_id, current_path)
            else:
                yield current_path, value[0] if value else ""

        for top_id in tree.get_children(""):
            root_label = tree.item(top_id, "text")
            try:
                hostname, rest = root_label.split(": ", 1)
                ip, endpoint = rest.split(" - ", 1)
            except ValueError:
                hostname, ip, endpoint = "Unknown", "Unknown", "Unknown"

            for path, value in walk_tree(top_id):
                if path and path[0] == root_label:
                    path = path[1:]
                full_path = ".".join(path)
                writer.writerow([hostname, ip, endpoint, full_path, value])

def show_help_guide(version):
    import os, sys, tkinter as tk
    from tkinter import ttk, Menu
    from tkinter import scrolledtext

    # ---------- helpers ----------
    def exe_name():
        # Always show the distributed exe name
        return "MultiSwitchCXplorer.exe"

    def section_title(parent, text):
        return ttk.Label(parent, text=text, font=("Segoe UI", 12, "bold"))

    def body_label(parent, text):
        return ttk.Label(parent, text=text, font=("Segoe UI", 10), justify="left")

    def code_block(parent, text_content, height=6):
        """
        Selectable, auto-wrapping code block with a Copy button.
        Visually wraps to window width (no horizontal scroll),
        but Copy always copies the original one-line string.
        """
        from tkinter import ttk
        from tkinter import scrolledtext
        import tkinter as tk

        raw_line = text_content.strip()  # preserve original single-line command

        frame = ttk.Frame(parent)
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(2, 4))

        ttk.Label(header, text="Example", font=("Segoe UI", 9, "bold")).pack(side="left")

        def copy_all():
            top = frame.winfo_toplevel()
            top.clipboard_clear()
            top.clipboard_append(raw_line)

        ttk.Button(header, text="Copy", command=copy_all).pack(side="right")

        # Use word wrap so it reflows on resize; no horizontal scrollbar
        txt = scrolledtext.ScrolledText(
            frame, wrap="word", height=height, font=("Consolas", 10)
        )
        txt.insert("1.0", raw_line + "\n")  # display-friendly; soft-wrap handles width
        txt.config(state="disabled", cursor="xterm")  # read-only but selectable
        txt.pack(fill="both", expand=True)

        # Right-click Copy (copies selected text; if none, copies the one-line)
        menu = tk.Menu(txt, tearoff=0)
        def copy_selection(event=None):
            try:
                sel = txt.get("sel.first", "sel.last")
            except tk.TclError:
                sel = ""
            top = frame.winfo_toplevel()
            top.clipboard_clear()
            top.clipboard_append(sel if sel else raw_line)
            return "break"
        menu.add_command(label="Copy", command=copy_selection)
        txt.bind("<Button-3>", lambda e: (menu.tk_popup(e.x_root, e.y_root), menu.grab_release()))
        txt.bind("<Control-c>", copy_selection)
        txt.bind("<Command-c>", copy_selection)

        return frame

    def make_scrollable(parent):
        """Return (container_frame, inner_frame) where inner_frame scrolls vertically."""
        container = ttk.Frame(parent)
        canvas = tk.Canvas(container, highlightthickness=0)
        vbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vbar.set)

        container.pack(fill="both", expand=True)
        canvas.pack(side="left", fill="both", expand=True)
        vbar.pack(side="right", fill="y")

        # Mouse wheel support
        def _on_mousewheel(event, canvas):
            """Safer mouse-wheel handler that ignores events after canvas is destroyed."""
            try:
                # If the canvas was destroyed between event scheduling and callback, this will raise
                if not canvas.winfo_exists():
                    return
                # Windows sends multiples of 120; Linux/Mac differ. Keep your existing behavior.
                if sys.platform.startswith("darwin"):
                    # macOS: event.delta is small; invert to match typical scroll direction if desired
                    canvas.yview_scroll(int(-event.delta), "units")
                else:
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except tk.TclError:
                # Widget is gone or not in a state to scroll - just ignore
                pass
        inner.bind_all("<MouseWheel>", _on_mousewheel)       # Windows
        inner.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-3, "units"))  # Linux
        inner.bind_all("<Button-5>", lambda e: canvas.yview_scroll( 3, "units"))  # Linux
        return container, inner

    # ---------- window ----------
    win = tk.Toplevel()
    win.title("Help - MultiSwitchCXplorer")
    win.geometry("980x700")
    win.minsize(820, 560)
    win.attributes("-topmost", True)
    win.focus_set()
    win.grab_set()

    # Header bar
    header = ttk.Frame(win)
    header.pack(fill="x", padx=12, pady=(12, 0))
    ttk.Label(header, text=f"MultiSwitchCXplorer v{version}", font=("Segoe UI", 14, "bold")).pack(side="left")
    ttk.Button(header, text="Close", command=win.destroy).pack(side="right")

    # Tabs
    tabs = ttk.Notebook(win)
    tabs.pack(fill="both", expand=True, padx=12, pady=12)

    # --- Quick Start tab ---
    quick = ttk.Frame(tabs)
    tabs.add(quick, text="Quick Start")

    section_title(quick, "Get started").pack(anchor="w", pady=(4, 6))
    body_label(quick,
        "1) Enter switch IPs/hostnames (one per line) in Target Switches.\n"
        "2) Enter API credentials.\n"
        "3) Choose how you want to run the request:\n"
        "   - Saved Requests tab: pick a saved request.\n"
        "   - Custom Request tab: set Endpoint, Version, Depth, Selector, and Attributes.\n"
        "4) Click 'Run API Requests' to fetch results.\n\n"
        "Use the Results tabs (JSON Viewer, Raw Response, Logs) to inspect output. "
        "Right-click keys/values in the JSON tree to copy, filter, or re-run an API request with fields populated."
    ).pack(anchor="w")

    ttk.Separator(quick).pack(fill="x", pady=10)

    section_title(quick, "Saved Requests").pack(anchor="w", pady=(6, 6))
    body_label(quick,
        "- Saved Requests are listed alphabetically.\n"
        "- Select a saved request to apply it.\n"
        "- Use 'Delete Saved Request' or right-click a name to remove it."
    ).pack(anchor="w")

    section_title(quick, "Custom Requests").pack(anchor="w", pady=(6, 6))
    body_label(quick,
        "- Use the Custom Request tab to set Endpoint, Version, Depth, Selector, and Attributes.\n"
        "- Click 'Save Current Request' to add it to Saved Requests."
    ).pack(anchor="w")

    section_title(quick, "Results & Exports").pack(anchor="w", pady=(6, 6))
    body_label(quick,
        "- JSON Viewer shows results as a tree you can filter.\n"
        "- Raw Response shows full JSON output with search.\n"
        "- Logs shows activity and errors.\n"
        "- Export filtered results to CSV from the JSON Viewer."
    ).pack(anchor="w")

    # --- CLI tab ---
    cli_tab = ttk.Frame(tabs)
    tabs.add(cli_tab, text="CLI")

    _, cli = make_scrollable(cli_tab)

    section_title(cli, "CLI flags (GUI autofill & Headless)").pack(anchor="w", pady=(4, 6))
    body_label(cli,
        "You can use the same CLI flags in two ways:\n"
        "- **GUI Autofill** - Launch the app with flags (without --headless) and the GUI fields will be pre-filled.\n"
        "- **Headless (CSV)** - Add --headless to run without the GUI and export results directly to CSV.\n\n"
        "Required in **headless** mode:\n"
        "  --headless            Run without GUI and export CSV\n"
        "  --username USER       API username\n"
        "  --device HOST         Single switch IP/hostname (use either --device or --device-file)\n"
        "  --device-file PATH    File of switches (one per line)\n"
        "  --output PATH         Output CSV file path\n\n"
        "Optional (for both GUI autofill and headless):\n"
        "  --password PASS       API password (if omitted, you will be prompted)\n"
        "  --verifyssl {true,false}   SSL verification (default: true)\n"
        "  --endpoint PATH            REST endpoint path (examples: system, system/interfaces)\n"
        "  --version VER              API version (e.g., 10.04, 10.11, 10.15)\n"
        "  --depth N                  Depth 1-10 (default: 1)\n"
        "  --selector {configuration,status,statistics}\n"
        "  --concurrency N            1-20 (default: 5)\n"
    ).pack(anchor="w")

    # Windows examples using MultiSwitchCXplorer.exe
    example_headless = fr"""
MultiSwitchCXplorer.exe --headless --username admin --password "P@ssw0rd!" --device-file .\switches.txt --endpoint system --version 10.11 --depth 1 --verifyssl false --concurrency 10 --output .\results.csv
""".strip("\n")

    example_gui_autofill = fr"""
MultiSwitchCXplorer.exe --username admin --device-file .\switches.txt --endpoint system/interfaces --selector status --version 10.15 --depth 2 --verifyssl true --concurrency 8
""".strip("\n")

    ttk.Separator(cli).pack(fill="x", pady=8)
    section_title(cli, "Headless example (Windows)").pack(anchor="w", pady=(4, 6))
    code_block(cli, example_headless, height=6).pack(fill="both", expand=False, pady=(0, 8))

    section_title(cli, "GUI autofill example (Windows)").pack(anchor="w", pady=(4, 6))
    body_label(cli, "Launches the GUI with fields pre-filled; click 'Run' to execute.").pack(anchor="w", pady=(0, 4))
    code_block(cli, example_gui_autofill, height=5).pack(fill="both", expand=False)

    # Footer
    footer = ttk.Frame(win)
    footer.pack(fill="x", padx=12, pady=(0, 12))
    ttk.Label(footer, text="(c) gregory.damron@hpe.com", font=("Segoe UI", 8)).pack(side="right")

def make_run_button(parent, command):
    btn = ttk.Button(parent, text="Run API Requests", command=command, style="PrimaryAction.TButton", width=22)
    return btn

def _walk_json_for_csv(data, parent_path=None):
    """
    Yield (key_path, value) leaves from arbitrary JSON.
    Skips the '__title__' helper key if present.
    """
    if parent_path is None:
        parent_path = []

    if isinstance(data, dict):
        for k, v in data.items():
            if k == "__title__":
                continue
            yield from _walk_json_for_csv(v, parent_path + [str(k)])
    elif isinstance(data, list):
        for i, item in enumerate(data):
            yield from _walk_json_for_csv(item, parent_path + [f"[{i}]"])
    else:
        # Primitive leaf
        yield (".".join(parent_path) if parent_path else "", data if data is not None else "")

def export_results_to_csv(all_json_results, filepath):
    """
    Headless CSV export using the in-memory results list (same schema as GUI).
    Writes rows: Hostname, IP/FQDN, API Endpoint, Key Path, Value
    If a result has an 'error', emits a single '(error)' row.
    """
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Hostname", "IP/FQDN", "API Endpoint", "Key Path", "Value"])

        for result in all_json_results:
            title = result.get("__title__", "Unknown: Unknown - Unknown")
            try:
                hostname, rest = title.split(": ", 1)
                ip, endpoint = rest.split(" - ", 1)
            except ValueError:
                hostname, ip, endpoint = "Unknown", "Unknown", "Unknown"

            if isinstance(result, dict) and "error" in result:
                writer.writerow([hostname, ip, endpoint, "(error)", result.get("error", "Unknown error")])
                continue

            for key_path, value in _walk_json_for_csv(result):
                # Skip the synthetic root label if present in path
                if key_path == "__title__":
                    continue
                writer.writerow([hostname, ip, endpoint, key_path, value])
