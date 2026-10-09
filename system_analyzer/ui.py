from __future__ import annotations

import json
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from .scanner import run_scan

APP_TITLE = "System Analysis Tool"
BG = "#f4f6fa"
CARD = "#ffffff"
INK = "#172033"
MUTED = "#667085"
BLUE = "#245fe5"
BORDER = "#e0e6ef"


class SystemAnalysisApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} 1.3.1")
        self.root.geometry("1320x880")
        self.root.minsize(1080, 720)
        self.root.configure(bg=BG)
        self.scan_result = None
        self.finding_by_iid = {}
        self._style()
        self._build()
        self._set_detail("Welcome to System Analysis Tool",
            "Start a scan to inspect this computer. Successful checks are shown alongside warnings and checks "
            "that could not be verified. This baseline version is read-only and does not automatically fix issues.")

    def _style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Segoe UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=INK)
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 22), foreground=INK, background=BG)
        style.configure("Muted.TLabel", font=("Segoe UI", 9), foreground=MUTED, background=BG)
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", padding=(18, 11), font=("Segoe UI Semibold", 9), background="#e9edf5", foreground="#344054")
        style.map("TNotebook.Tab", background=[("selected", CARD), ("active", "#dce6fb")],
                  foreground=[("selected", BLUE), ("active", INK)])
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=29, background=CARD, fieldbackground=CARD)
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9), padding=(9, 10), background="#edf1f7", foreground="#344054")
        style.map("Treeview.Heading", background=[("active", "#e2e8f0")])
        style.configure("Primary.TButton", font=("Segoe UI Semibold", 10), padding=(14, 9))
        style.configure("TButton", padding=(10, 7))
        style.map("Treeview", background=[("selected", "#dce8ff")], foreground=[("selected", INK)])

    def _build(self):
        outer = ttk.Frame(self.root, padding=(24, 20, 24, 18))
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 14))
        brand = ttk.Frame(header)
        brand.pack(side="left", fill="x", expand=True)
        row = ttk.Frame(brand)
        row.pack(anchor="w")
        tk.Label(row, text="SA", font=("Segoe UI Semibold", 12), fg="white", bg=BLUE,
                 width=3, padx=3, pady=5).pack(side="left", padx=(0, 12))
        ttk.Label(row, text=APP_TITLE, style="Title.TLabel").pack(side="left")
        ttk.Label(brand, text="Local diagnostics • Clear findings • Recommended next steps",
                  style="Muted.TLabel").pack(anchor="w", pady=(5, 0))
        self.scan_btn = ttk.Button(header, text="▶  Start system scan", style="Primary.TButton", command=self.start_scan)
        self.scan_btn.pack(side="right", padx=(10, 0))
        self.export_btn = ttk.Button(header, text="Export report", command=self.export_report, state="disabled")
        self.export_btn.pack(side="right")

        self.status_var = tk.StringVar(value="Ready to scan · No changes will be made")
        status = tk.Frame(outer, bg="#eaf1ff", padx=12, pady=9)
        status.pack(fill="x", pady=(0, 14))
        tk.Label(status, text="●", bg="#eaf1ff", fg=BLUE).pack(side="left", padx=(0, 8))
        tk.Label(status, textvariable=self.status_var, bg="#eaf1ff", fg="#244581",
                 font=("Segoe UI", 9)).pack(side="left")

        cards = ttk.Frame(outer)
        cards.pack(fill="x", pady=(0, 14))
        self.metric_vars = {}
        metrics = [
            ("health", "OVERALL STATUS", "Awaiting scan", "Based on available checks"),
            ("findings", "FINDINGS", "—", "Warnings and items to review"),
            ("high", "HIGH PRIORITY", "—", "High and critical findings"),
            ("checks", "CHECKS", "—", "Passed, review, warning, unknown"),
        ]
        for i, (key, label, initial, note) in enumerate(metrics):
            card = tk.Frame(cards, bg=CARD, highlightbackground=BORDER, highlightthickness=1, padx=14, pady=12)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 9, 0))
            cards.grid_columnconfigure(i, weight=1, uniform="metric")
            tk.Label(card, text=label, bg=CARD, fg=MUTED, font=("Segoe UI Semibold", 8)).pack(anchor="w")
            var = tk.StringVar(value=initial)
            self.metric_vars[key] = var
            tk.Label(card, textvariable=var, bg=CARD, fg=INK, font=("Segoe UI Semibold", 17)).pack(anchor="w", pady=(7, 2))
            tk.Label(card, text=note, bg=CARD, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")

        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self.overview_tab = ttk.Frame(self.tabs, padding=10)
        self.findings_tab = ttk.Frame(self.tabs, padding=10)
        self.startup_tab = ttk.Frame(self.tabs, padding=10)
        self.process_tab = ttk.Frame(self.tabs, padding=10)
        self.events_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.overview_tab, text="  Overview & checks  ")
        self.tabs.add(self.findings_tab, text="  Findings & fixes  ")
        self.tabs.add(self.events_tab, text="  Event log details  ")
        self.tabs.add(self.startup_tab, text="  Startup inventory  ")
        self.tabs.add(self.process_tab, text="  Top processes  ")

        ttk.Label(self.overview_tab, text="Diagnostic check results", font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 8))
        self.check_tree = self._tree(self.overview_tab, ("status", "category", "name", "evidence"),
                                     ("STATUS", "CATEGORY", "CHECK", "EVIDENCE"),
                                     (105, 120, 220, 580))
        self.check_tree.tag_configure("Warning", foreground="#b42318")
        self.check_tree.tag_configure("Unknown", foreground="#7a5a00")
        self.check_tree.tag_configure("Review", foreground="#8a5a00")
        self.check_tree.tag_configure("Passed", foreground="#167647")

        finding_split = ttk.Panedwindow(self.findings_tab, orient="horizontal")
        finding_split.pack(fill="both", expand=True)
        find_left = ttk.Frame(finding_split)
        find_right = tk.Frame(finding_split, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        finding_split.add(find_left, weight=3)
        finding_split.add(find_right, weight=2)
        self.finding_tree = self._tree(find_left, ("severity", "category", "title"),
                                       ("SEVERITY", "CATEGORY", "FINDING"), (90, 120, 390))
        self.finding_tree.bind("<<TreeviewSelect>>", self._on_finding_select)
        self.finding_tree.tag_configure("High", foreground="#b42318")
        self.finding_tree.tag_configure("Medium", foreground="#8a5a00")
        self.finding_tree.tag_configure("Info", foreground=MUTED)
        self.finding_tree.tag_configure("Low", foreground=MUTED)
        self.finding_tree.tag_configure("Critical", foreground="#b42318")
        tk.Label(find_right, text="FINDING DETAILS", bg=CARD, fg=MUTED,
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=14, pady=(14, 4))
        self.finding_title = tk.Label(find_right, text="Select a finding", bg=CARD, fg=INK,
                                      font=("Segoe UI Semibold", 12), justify="left", anchor="w", wraplength=330)
        self.finding_title.pack(fill="x", padx=14, pady=(0, 8))
        self.finding_detail = tk.Text(find_right, wrap="word", bg=CARD, fg=INK, font=("Segoe UI", 9),
                                      relief="flat", padx=14, pady=4, borderwidth=0)
        self.finding_detail.pack(fill="both", expand=True)
        self.finding_detail.configure(state="disabled")

        ttk.Label(self.events_tab, text="Recent critical/error events from the Windows System log", font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 4))
        ttk.Label(self.events_tab, text="Up to 30 events from the last 7 days. Event counts are triage signals, not diagnoses.", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.event_tree = self._tree(self.events_tab, ("time", "level", "source", "event_id", "message"),
                                     ("TIME", "LEVEL", "SOURCE", "EVENT ID", "MESSAGE"),
                                     (175, 90, 180, 80, 650))
        self.event_tree.tag_configure("Critical", foreground="#b42318")
        self.event_tree.tag_configure("Error", foreground="#b42318")

        ttk.Label(self.startup_tab, text="Common Windows Run-key entries", font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 4))
        ttk.Label(self.startup_tab, text="Inventory only: unfamiliar entries are not automatically malicious. Review before disabling anything.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.startup_tree = self._tree(self.startup_tab, ("scope", "name", "command"),
                                       ("SCOPE", "ENTRY NAME", "COMMAND"), (145, 230, 700))

        ttk.Label(self.process_tab, text="Processes using the most memory at scan time", font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(0, 8))
        self.process_tree = self._tree(self.process_tab, ("name", "pid", "memory", "cpu", "path"),
                                       ("PROCESS", "PID", "MEMORY", "CPU SAMPLE", "EXECUTABLE PATH"),
                                       (210, 80, 110, 110, 550))

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(10, 0))
        ttk.Label(footer, text="Read-only baseline checks · Not a guarantee that a PC is malware-free",
                  style="Muted.TLabel").pack(side="left")
        ttk.Label(footer, text="Version 1.3.1", style="Muted.TLabel").pack(side="right")

    def _tree(self, parent, columns, headings, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for col, heading, width in zip(columns, headings, widths):
            tree.heading(col, text=heading)
            tree.column(col, width=width, minwidth=70, stretch=(col in ("evidence", "title", "command", "path")))
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    def _set_detail(self, title, body):
        self.finding_title.configure(text=title)
        self.finding_detail.configure(state="normal")
        self.finding_detail.delete("1.0", "end")
        self.finding_detail.insert("1.0", body)
        self.finding_detail.configure(state="disabled")

    def start_scan(self):
        self.scan_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.status_var.set("Scan in progress · Collecting local diagnostics…")
        for tree in (self.check_tree, self.finding_tree, self.startup_tree, self.process_tree, self.event_tree):
            for item in tree.get_children():
                tree.delete(item)
        self.scan_result = None
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            result = run_scan()
            self.root.after(0, lambda: self._scan_complete(result))
        except Exception as exc:
            self.root.after(0, lambda: self._scan_failed(str(exc)))

    def _scan_complete(self, result):
        self.scan_result = result
        summary = result.get("summary", {})
        findings = result.get("findings", [])
        checks = result.get("checks", [])
        for c in checks:
            self.check_tree.insert("", "end", values=(c["status"], c["category"], c["name"], c["evidence"]), tags=(c["status"],))
        self.finding_by_iid.clear()
        for i, f in enumerate(findings):
            iid = str(i)
            self.finding_by_iid[iid] = f
            self.finding_tree.insert("", "end", iid=iid,
                values=(f["severity"], f["category"], f["title"]), tags=(f["severity"],))
        details = result.get("details", {})
        win_diag = details.get("windows_diagnostics", {})
        event_data = win_diag.get("recent_system_events", {})
        event_items = event_data.get("Events", []) if isinstance(event_data, dict) else []
        for event in event_items:
            event_time = str(event.get("TimeCreated") or "Unknown")
            # Convert ISO timestamp to a compact local display where possible.
            try:
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                pass
            self.event_tree.insert("", "end", values=(
                event_time, event.get("Level", "Unknown"), event.get("ProviderName", "Unknown"),
                event.get("Id", ""), event.get("Message", "No message available")
            ), tags=(str(event.get("Level", "")),))
        if not event_items:
            event_reason = event_data.get("reason") if isinstance(event_data, dict) else None
            note = "No matching events were returned." if not event_reason else f"Event query unavailable: {event_reason}"
            self.event_tree.insert("", "end", values=("", "Info", "System log", "", note))

        for s in details.get("startup_entries", []):
            self.startup_tree.insert("", "end", values=(s.get("scope", ""), s.get("name", ""), s.get("command", "")))
        for p in details.get("top_processes_by_memory", []):
            if not isinstance(p, dict):
                continue
            mb = p.get("memory_bytes", 0) / (1024 * 1024)
            self.process_tree.insert("", "end", values=(p.get("name", ""), p.get("pid", ""),
                f"{mb:.0f} MB", f"{p.get('cpu_percent', 0):.1f}%", p.get("executable") or "Unavailable"))

        self.metric_vars["findings"].set(str(len(findings)))
        self.metric_vars["high"].set(str(summary.get("high", 0) + summary.get("critical", 0)))
        counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("Passed", "Warning", "Review", "Unknown")}
        self.metric_vars["checks"].set(f"{len(checks)} ({counts['Passed']} passed)")
        if counts["Warning"] or summary.get("high", 0) or summary.get("critical", 0):
            status = "Needs attention"
        elif counts["Unknown"]:
            status = "Partially checked"
        elif counts["Review"]:
            status = "Review advised"
        else:
            status = "No major flags"
        self.metric_vars["health"].set(status)
        self.status_var.set(f"Scan completed · {len(checks)} checks reported · {len(findings)} finding(s) · No settings changed")
        self.scan_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        self.tabs.select(self.overview_tab)
        if findings:
            iid = self.finding_tree.get_children()[0]
            self.finding_tree.selection_set(iid)
            self._on_finding_select()
        else:
            self._set_detail("No findings generated", "No current rules triggered. This does not prove that the computer is fully secure.")

    def _scan_failed(self, error):
        self.scan_btn.configure(state="normal")
        self.status_var.set("Scan failed")
        messagebox.showerror("System scan failed", error)

    def _on_finding_select(self, _event=None):
        selected = self.finding_tree.selection()
        if not selected:
            return
        f = self.finding_by_iid.get(selected[0])
        if not f:
            return
        self._set_detail(f["title"], (
            f"SEVERITY: {f['severity']}    CONFIDENCE: {f['confidence']}\n"
            f"CATEGORY: {f['category']}\n\nEVIDENCE\n{f['evidence']}\n\n"
            f"RECOMMENDED ACTION\n{f['recommendation']}\n\nHOW TO VERIFY\n{f['verification']}\n\n"
            "Review the evidence before making changes. A warning or unfamiliar entry is not automatically proof of malware."
        ))

    def export_report(self):
        if not self.scan_result:
            return
        name = f"system-analysis-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        path = filedialog.asksaveasfilename(title="Export scan report", defaultextension=".json",
            initialfile=name, filetypes=[("JSON report", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.scan_result, handle, indent=2, ensure_ascii=False)
            messagebox.showinfo("Report exported", f"Report saved to:\n{path}\n\nReview it before sharing; it can contain process paths and startup commands.")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))


def run_app():
    root = tk.Tk()
    SystemAnalysisApp(root)
    root.mainloop()
