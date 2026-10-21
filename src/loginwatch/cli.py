import json
from loginwatch.ssh_parser import load_ssh
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from loginwatch.detector import detect
from loginwatch.parser import LogParseError, load_csv

app = typer.Typer(
    help="Detect suspicious login activity in authentication logs.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
error_console = Console(stderr=True)


def fail(message: str) -> None:
    error_console.print(f"Error: {message}", style="red", markup=False)
    raise typer.Exit(code=1)


def select_log_file() -> Path | None:
    """Open a file picker and return the selected path."""
    message = (
        "The file picker is unavailable. "
        "Pass the file path directly: loginwatch analyze PATH"
    )

    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError as exc:
        raise RuntimeError(message) from exc

    try:
        root = tk.Tk()
        root.withdraw()

        try:
            selected = filedialog.askopenfilename(
                parent=root,
                title="Select an authentication log",
                filetypes=[
                    ("Authentication logs", "*.csv *.log *.txt"),
                    ("All files", "*.*"),
                ],
            )
        finally:
            root.destroy()
    except tk.TclError as exc:
        raise RuntimeError(message) from exc

    return Path(selected) if selected else None


def save_report(destination: Path, report: dict, source: Path) -> Path:
    """Save a new report without overwriting an existing file."""
    destination = destination.expanduser().resolve()

    if destination == source:
        raise ValueError("The report path must differ from the input path.")

    content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation prevents accidental overwrites.
    with destination.open("x", encoding="utf-8") as file:
        file.write(content)

    return destination


@app.callback()
def main() -> None:
    """LoginWatch — authentication log analysis."""


@app.command()
def analyze(
    log_file: Annotated[
        Path | None,
        typer.Argument(
            help="Path to an authentication log. Omit to open the file picker.",
        ),
    ] = None,
        log_format: Annotated[
        str,
        typer.Option(
            "--format",
            help="Input format: csv or ssh.",
        ),
    ] = "csv",
    year: Annotated[
        int | None,
        typer.Option(
            "--year",
            min=1,
            max=9999,
            help="Year for SSH logs without a year. Times are treated as UTC.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Save a new JSON report."),
    ] = None,
    window: Annotated[
        int,
        typer.Option(
            "--window",
            min=1,
            help="Detection window in seconds.",
        ),
    ] = 300,
    failure_threshold: Annotated[
        int,
        typer.Option(
            "--failure-threshold",
            min=1,
            help="Failed attempts from one IP required for an alert.",
        ),
    ] = 5,
    username_threshold: Annotated[
        int,
        typer.Option(
            "--username-threshold",
            min=1,
            help="Distinct usernames targeted by one IP required for an alert.",
        ),
    ] = 3,
    success_threshold: Annotated[
        int,
        typer.Option(
            "--success-threshold",
            min=1,
            help="Failures before a successful login required for an alert.",
        ),
    ] = 3,
) -> None:
    """Analyze authentication logs and display suspicious activity."""
    if log_file is None:
        try:
            log_file = select_log_file()
        except RuntimeError as exc:
            fail(str(exc))

        if log_file is None:
            console.print("No file selected. Analysis cancelled.")
            raise typer.Exit()

        log_format = log_format.strip().lower()

    if log_format not in {"csv", "ssh"}:
        fail("Unsupported format. Choose --format csv or --format ssh.")

    if year is not None and log_format != "ssh":
        fail("--year is only supported with --format ssh.")

    try:
        source = log_file.expanduser().resolve()

        if log_format == "ssh":
            events = load_ssh(source, year=year)
        else:
            events = load_csv(source)
    except (LogParseError, OSError, RuntimeError) as exc:
        fail(str(exc))

    alerts = detect(
        events,
        window_seconds=window,
        failure_threshold=failure_threshold,
        username_threshold=username_threshold,
        success_threshold=success_threshold,
    )

    failed = sum(not event.success for event in events)
    severity_counts = Counter(alert.severity for alert in alerts)

    console.print("\nLoginWatch", style="bold cyan")
    console.print(f"Input: {source}", markup=False)
    console.print(
        f"Events: {len(events)} | "
        f"Successful: {len(events) - failed} | "
        f"Failed: {failed} | "
        f"Unique IPs: {len({event.ip for event in events})}"
    )
    console.print(
        f"Alerts: {len(alerts)} | "
        f"High: {severity_counts['high']} | "
        f"Medium: {severity_counts['medium']}\n"
    )

    if alerts:
        table = Table(title="Suspicious Login Activity")
        table.add_column("Time (UTC)")
        table.add_column("Severity")
        table.add_column("IP Address")
        table.add_column("Rule")
        table.add_column("Details")

        for alert in alerts:
            color = "red" if alert.severity == "high" else "yellow"
            table.add_row(
                alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                alert.severity.upper(),
                alert.ip,
                alert.rule.replace("_", " ").title(),
                alert.description,
                style=color,
            )

        console.print(table)
        console.print(
            "\nAlerts indicate suspicious patterns and require review.",
            style="dim",
        )
    else:
        console.print(
            "No suspicious activity detected with the current thresholds.",
            style="green",
        )

    if output is not None:
        serialized_alerts = []

        for alert in alerts:
            item = asdict(alert)
            item["timestamp"] = alert.timestamp.isoformat()
            serialized_alerts.append(item)

        report = {
            "schema_version": 1,
            "input": str(source),
            "settings": {
                "window_seconds": window,
                "failure_threshold": failure_threshold,
                "username_threshold": username_threshold,
                "success_threshold": success_threshold,
            },
            "summary": {
                "events": len(events),
                "successful_logins": len(events) - failed,
                "failed_logins": failed,
                "unique_ips": len({event.ip for event in events}),
                "alerts": len(alerts),
                "alerts_by_severity": {
                    "high": severity_counts["high"],
                    "medium": severity_counts["medium"],
                },
            },
            "alerts": serialized_alerts,
        }

        try:
            saved_path = save_report(output, report, source)
        except FileExistsError:
            fail(
                "The report already exists. Choose a different output "
                "filename or remove the existing report."
            )
        except (OSError, ValueError, RuntimeError) as exc:
            fail(f"Cannot save report: {exc}")

        console.print(f"\nReport saved: {saved_path}", markup=False)


if __name__ == "__main__":
    app()