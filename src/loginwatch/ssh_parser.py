import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

from loginwatch.parser import LoginEvent, LogParseError, parse_timestamp


PREFIX = re.compile(
    r"^(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\S+"
    r")\s+"
    r".*?\bsshd(?:-session)?\[\d+\]:\s+"
    r"(?P<message>.*)$"
)

LOGIN = re.compile(
    r"^(?P<result>Failed|Accepted) "
    r"(?P<method>password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?:invalid user )?"
    r"(?P<username>\S+) "
    r"from (?P<ip>\S+) "
    r"port \d+\b"
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def load_ssh(file_path: Path, year: int | None = None) -> list[LoginEvent]:
    """Read supported OpenSSH authentication events.

    Traditional syslog timestamps require an explicit year and are
    interpreted as UTC. ISO timestamps preserve their UTC offset.
    Unrelated log messages are ignored.
    """
    events = []

    try:
        with file_path.open(encoding="utf-8-sig") as file:
            for line_number, line in enumerate(file, start=1):
                prefix = PREFIX.match(line.strip())
                if prefix is None:
                    continue

                login = LOGIN.match(prefix["message"])
                if login is None:
                    continue

                raw_timestamp = prefix["timestamp"]

                if raw_timestamp[0].isdigit():
                    timestamp = parse_timestamp(raw_timestamp, line_number)
                else:
                    if year is None:
                        raise LogParseError(
                            f"Line {line_number}: this SSH timestamp has no "
                            "year. Provide --year, for example --year 2026."
                        )

                    month, day, clock = raw_timestamp.split()
                    hour, minute, second = map(int, clock.split(":"))

                    try:
                        timestamp = datetime(
                            year=year,
                            month=MONTHS[month],
                            day=int(day),
                            hour=hour,
                            minute=minute,
                            second=second,
                            tzinfo=timezone.utc,
                        )
                    except (ValueError, KeyError) as exc:
                        raise LogParseError(
                            f"Line {line_number}: invalid SSH timestamp "
                            f"{raw_timestamp!r}."
                        ) from exc

                try:
                    ip = str(ipaddress.ip_address(login["ip"]))
                except ValueError as exc:
                    raise LogParseError(
                        f"Line {line_number}: invalid IP address "
                        f"{login['ip']!r}."
                    ) from exc

                events.append(
                    LoginEvent(
                        timestamp=timestamp,
                        ip=ip,
                        username=login["username"],
                        success=login["result"] == "Accepted",
                        line_number=line_number,
                    )
                )

    except UnicodeError as exc:
        raise LogParseError(
            "Cannot decode the file. Save it with UTF-8 encoding."
        ) from exc
    except OSError as exc:
        raise LogParseError(f"Cannot read the file: {exc}") from exc

    if not events:
        raise LogParseError(
            "No supported SSH login events found. Expected OpenSSH "
            "'Failed' or 'Accepted' authentication messages."
        )

    return sorted(events, key=lambda event: event.timestamp)