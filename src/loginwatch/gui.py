import json
import queue
import threading
import tkinter as tk
import sys
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from loginwatch.detector import detect
from loginwatch.parser import load_csv
from loginwatch.ssh_parser import load_ssh


class LoginWatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LoginWatch")
        self.root.geometry("1150x700")
        self.root.minsize(850, 550)

        self.messages = queue.Queue()
        self.report = None

        self.file_path = tk.StringVar()
        self.log_format = tk.StringVar(value="csv")
        self.year = tk.StringVar()
        self.status = tk.StringVar(value="Select a log file to begin.")

        self.settings = {
            "window_seconds": tk.StringVar(value="300"),
            "failure_threshold": tk.StringVar(value="5"),
            "username_threshold": tk.StringVar(value="3"),
            "success_threshold": tk.StringVar(value="3"),
        }

        self.build_interface()
        self.root.after(100, self.check_messages)

    def build_interface(self):
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(6, weight=1)

        ttk.Label(
            main,
            text="LoginWatch",
            font=("Segoe UI", 24, "bold"),
        ).grid(row=0, column=0, columnspan=3, sticky="w")

        ttk.Label(
            main,
            text="Analyze authentication logs for suspicious login activity.",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 18))

        ttk.Label(main, text="Log file").grid(row=2, column=0, sticky="w")

        ttk.Entry(main, textvariable=self.file_path).grid(
            row=2, column=1, sticky="ew", padx=10
        )

        ttk.Button(main, text="Browse...", command=self.browse).grid(
            row=2, column=2
        )

        options = ttk.Frame(main)
        options.grid(
            row=3, column=0, columnspan=3, sticky="ew", pady=15
        )

        ttk.Label(options, text="Format").pack(side="left")

        format_box = ttk.Combobox(
            options,
            textvariable=self.log_format,
            values=("csv", "ssh"),
            state="readonly",
            width=8,
        )
        format_box.pack(side="left", padx=(8, 20))
        format_box.bind("<<ComboboxSelected>>", self.update_year_state)

        ttk.Label(options, text="SSH year").pack(side="left")

        self.year_entry = ttk.Entry(
            options,
            textvariable=self.year,
            width=8,
            state="disabled",
        )
        self.year_entry.pack(side="left", padx=8)

        ttk.Label(
            options,
            text="Required for SSH timestamps without a year; interpreted as UTC.",
        ).pack(side="left", padx=8)

        advanced = ttk.LabelFrame(main, text="Detection settings", padding=10)
        advanced.grid(row=4, column=0, columnspan=3, sticky="ew")

        labels = (
            ("window_seconds", "Window (seconds)"),
            ("failure_threshold", "Failed attempts"),
            ("username_threshold", "Distinct usernames"),
            ("success_threshold", "Failures before success"),
        )

        for column, (key, label) in enumerate(labels):
            advanced.columnconfigure(column, weight=1)
            ttk.Label(advanced, text=label).grid(
                row=0, column=column, sticky="w", padx=8
            )
            ttk.Entry(
                advanced,
                textvariable=self.settings[key],
                width=12,
            ).grid(row=1, column=column, sticky="ew", padx=8, pady=5)

        actions = ttk.Frame(main)
        actions.grid(
            row=5, column=0, columnspan=3, sticky="ew", pady=15
        )

        self.analyze_button = ttk.Button(
            actions,
            text="Analyze",
            command=self.start_analysis,
        )
        self.analyze_button.pack(side="left")

        self.export_button = ttk.Button(
            actions,
            text="Export JSON...",
            command=self.export_report,
            state="disabled",
        )
        self.export_button.pack(side="left", padx=10)

        self.progress = ttk.Progressbar(actions, mode="indeterminate")
        self.progress.pack(side="right", fill="x", expand=True, padx=10)

        results = ttk.Frame(main)
        results.grid(row=6, column=0, columnspan=3, sticky="nsew")
        results.rowconfigure(0, weight=1)
        results.columnconfigure(0, weight=1)

        columns = ("time", "severity", "ip", "rule", "details")
        self.table = ttk.Treeview(
            results,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = (
            ("time", "Time (UTC)", 160),
            ("severity", "Severity", 80),
            ("ip", "IP Address", 130),
            ("rule", "Rule", 210),
            ("details", "Details", 450),
        )

        for key, title, width in headings:
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=70)

        vertical = ttk.Scrollbar(
            results, orient="vertical", command=self.table.yview
        )
        horizontal = ttk.Scrollbar(
            results, orient="horizontal", command=self.table.xview
        )
        self.table.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        self.table.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

        self.table.tag_configure("high", foreground="#b42318")
        self.table.tag_configure("medium", foreground="#925700")

        ttk.Label(main, textvariable=self.status, wraplength=1000).grid(
            row=7, column=0, columnspan=3, sticky="w", pady=(12, 5)
        )

        ttk.Label(
            main,
            text="Alerts indicate suspicious patterns and require review.",
        ).grid(row=8, column=0, columnspan=3, sticky="w")

    def browse(self):
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="Select an authentication log",
            filetypes=[
                ("Authentication logs", "*.csv *.log *.txt"),
                ("All files", "*.*"),
            ],
        )
        if selected:
            self.file_path.set(selected)

    def update_year_state(self, _event=None):
        state = "normal" if self.log_format.get() == "ssh" else "disabled"
        self.year_entry.configure(state=state)

    def start_analysis(self):
        try:
            raw_path = self.file_path.get().strip()
            if not raw_path:
                raise ValueError("Select a log file first.")

            source = Path(raw_path).expanduser().resolve()
            if not source.is_file():
                raise ValueError("The selected path is not a file.")

            settings = {}
            for key, variable in self.settings.items():
                try:
                    value = int(variable.get())
                except ValueError:
                    raise ValueError(
                        "All detection settings must be positive integers."
                    ) from None

                if value < 1:
                    raise ValueError(
                        "All detection settings must be positive integers."
                    )
                settings[key] = value

            log_format = self.log_format.get()
            year = None

            if log_format == "ssh" and self.year.get().strip():
                try:
                    year = int(self.year.get())
                except ValueError:
                    raise ValueError(
                        "SSH year must be an integer between 1 and 9999."
                    ) from None

                if not 1 <= year <= 9999:
                    raise ValueError("SSH year must be between 1 and 9999.")

        except (ValueError, OSError, RuntimeError) as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self.root)
            return

        self.report = None
        self.table.delete(*self.table.get_children())
        self.export_button.configure(state="disabled")
        self.analyze_button.configure(state="disabled")
        self.status.set(f"Analyzing {source.name}...")
        self.progress.start(10)

        # Capture input values before starting the worker.
        threading.Thread(
            target=self.run_analysis,
            args=(source, log_format, year, settings),
            daemon=True,
        ).start()

    def run_analysis(self, source, log_format, year, settings):
        # Background workers communicate through the queue, never Tk widgets.
        try:
            events = (
                load_ssh(source, year=year)
                if log_format == "ssh"
                else load_csv(source)
            )
            alerts = detect(events, **settings)
            failed = sum(not event.success for event in events)

            serialized = []
            for alert in alerts:
                item = asdict(alert)
                item["timestamp"] = alert.timestamp.isoformat()
                serialized.append(item)

            report = {
                "schema_version": 1,
                "input": str(source),
                "format": log_format,
                "ssh_year": year,
                "settings": settings,
                "summary": {
                    "events": len(events),
                    "successful_logins": len(events) - failed,
                    "failed_logins": failed,
                    "unique_ips": len({event.ip for event in events}),
                    "alerts": len(alerts),
                    "alerts_by_severity": {
                        "high": sum(a.severity == "high" for a in alerts),
                        "medium": sum(a.severity == "medium" for a in alerts),
                    },
                },
                "alerts": serialized,
            }

            self.messages.put(("success", report))
        except Exception as exc:
            self.messages.put(("error", str(exc)))

    def check_messages(self):
        try:
            result, payload = self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.progress.stop()
            self.analyze_button.configure(state="normal")

            if result == "error":
                self.status.set("Analysis failed. Review the error and try again.")
                messagebox.showerror(
                    "Analysis failed", payload, parent=self.root
                )
            else:
                self.show_report(payload)

        self.root.after(100, self.check_messages)

    def show_report(self, report):
        self.report = report

        for alert in report["alerts"]:
            self.table.insert(
                "",
                "end",
                values=(
                    alert["timestamp"],
                    alert["severity"].upper(),
                    alert["ip"],
                    alert["rule"].replace("_", " ").title(),
                    alert["description"],
                ),
                tags=(alert["severity"],),
            )

        summary = report["summary"]
        self.status.set(
            f"Analyzed: {report['input']} | "
            f"Events: {summary['events']} | "
            f"Successful: {summary['successful_logins']} | "
            f"Failed: {summary['failed_logins']} | "
            f"Unique IPs: {summary['unique_ips']} | "
            f"Alerts: {summary['alerts']}"
            + (
                " | No suspicious activity detected with these settings."
                if not report["alerts"]
                else ""
            )
        )
        self.export_button.configure(state="normal")

    def export_report(self):
        if self.report is None:
            return

        selected = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export JSON report — choose a new filename",
            defaultextension=".json",
            initialfile="loginwatch-report.json",
            filetypes=[("JSON report", "*.json")],
        )
        if not selected:
            return

        try:
            destination = Path(selected).expanduser().resolve()
            source = Path(self.report["input"])

            if destination == source:
                raise ValueError("The report cannot replace the input log.")

            content = json.dumps(
                self.report, indent=2, ensure_ascii=False
            ) + "\n"

            with destination.open("x", encoding="utf-8") as file:
                file.write(content)

        except FileExistsError:
            messagebox.showerror(
                "Export failed",
                "This file already exists. Choose a new filename.",
                parent=self.root,
            )
            return
        except (OSError, ValueError, RuntimeError) as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)
            return

        messagebox.showinfo(
            "Report exported",
            f"Report saved to:\n{destination}",
            parent=self.root,
        )


def main():
    root = tk.Tk()

    if getattr(sys, "frozen", False):
        assets_dir = Path(sys._MEIPASS) / "assets"
    else:
        assets_dir = Path(__file__).resolve().parents[2] / "assets"

    icon = tk.PhotoImage(file=str(assets_dir / "loginwatch.png"))
    root.iconphoto(True, icon)

    root.loginwatch_icon = icon

    LoginWatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()