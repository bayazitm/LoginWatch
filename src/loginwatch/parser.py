import csv
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class LogParseError(ValueError):
    """Raised when a log file contains invalid data."""


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    ip: str
    username: str
    success: bool
    line_number: int


REQUIRED_COLUMNS = {"timestamp", "ip", "username", "success"}


def parse_timestamp(value: str, line_number: int) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise LogParseError(
            f"Line {line_number}: invalid timestamp {value!r}. "
            "Use ISO 8601, for example 2026-10-21T10:00:00+00:00."
        ) from exc

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def load_csv(file_path: Path) -> list[LoginEvent]:
    """Read and validate CSV events, then sort them chronologically."""
    events = []

    try:
        with file_path.open(encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file, strict=True)

            if reader.fieldnames is None:
                raise LogParseError("The file is empty or has no CSV header.")

            columns = [name.strip() for name in reader.fieldnames]

            if len(columns) != len(set(columns)):
                raise LogParseError("The CSV header contains duplicate columns.")

            missing = REQUIRED_COLUMNS - set(columns)
            if missing:
                raise LogParseError(
                    "Missing required columns: " + ", ".join(sorted(missing))
                )

            reader.fieldnames = columns

            for row in reader:
                line_number = reader.line_num

                if None in row:
                    raise LogParseError(
                        f"Line {line_number}: more values than header columns."
                    )

                if any(value is None for value in row.values()):
                    raise LogParseError(
                        f"Line {line_number}: fewer values than header columns."
                    )

                values = {
                    name: row[name].strip()
                    for name in REQUIRED_COLUMNS
                }

                for name, value in values.items():
                    if not value:
                        raise LogParseError(
                            f"Line {line_number}: {name!r} cannot be empty."
                        )

                timestamp = parse_timestamp(
                    values["timestamp"], line_number
                )

                try:
                    ip = str(ipaddress.ip_address(values["ip"]))
                except ValueError as exc:
                    raise LogParseError(
                        f"Line {line_number}: invalid IP address "
                        f"{values['ip']!r}."
                    ) from exc

                success_text = values["success"].lower()
                if success_text not in {"true", "false"}:
                    raise LogParseError(
                        f"Line {line_number}: success must be true or false."
                    )

                events.append(
                    LoginEvent(
                        timestamp=timestamp,
                        ip=ip,
                        username=values["username"],
                        success=success_text == "true",
                        line_number=line_number,
                    )
                )

    except UnicodeError as exc:
        raise LogParseError(
            "Cannot decode the file. Save it with UTF-8 encoding."
        ) from exc
    except csv.Error as exc:
        raise LogParseError(f"Invalid CSV format: {exc}") from exc
    except OSError as exc:
        raise LogParseError(f"Cannot read the file: {exc}") from exc

    if not events:
        raise LogParseError("The file contains no login events.")

    return sorted(events, key=lambda event: event.timestamp)