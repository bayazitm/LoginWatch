from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from loginwatch.parser import LoginEvent


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    timestamp: datetime
    ip: str
    description: str


def detect(
    events: Iterable[LoginEvent],
    window_seconds: int = 300,
    failure_threshold: int = 5,
    username_threshold: int = 3,
    success_threshold: int = 3,
) -> list[Alert]:
    """Detect suspicious activity within a rolling time window."""
    settings = (
        window_seconds,
        failure_threshold,
        username_threshold,
        success_threshold,
    )
    if any(value < 1 for value in settings):
        raise ValueError("Detection settings must be positive integers.")

    window = timedelta(seconds=window_seconds)
    failures_by_ip = defaultdict(deque)
    failures_by_account = defaultdict(deque)

    alerts = []

    emitted = set()

    for event in sorted(events, key=lambda item: item.timestamp):
        cutoff = event.timestamp - window

        ip_failures = failures_by_ip[event.ip]
        account_key = (event.ip, event.username)
        account_failures = failures_by_account[account_key]

        while ip_failures and ip_failures[0].timestamp < cutoff:
            ip_failures.popleft()

        while account_failures and account_failures[0].timestamp < cutoff:
            account_failures.popleft()

        if event.success:
            if len(account_failures) >= success_threshold:
                alerts.append(
                    Alert(
                        rule="success_after_failures",
                        severity="high",
                        timestamp=event.timestamp,
                        ip=event.ip,
                        description=(
                            f"Successful login for {event.username!r} after "
                            f"{len(account_failures)} failed attempts from "
                            f"the same IP within {window_seconds} seconds."
                        ),
                    )
                )

            account_failures.clear()
            continue

        ip_failures.append(event)
        account_failures.append(event)

        failure_key = ("repeated_failed_logins", event.ip)

        if (
            len(ip_failures) >= failure_threshold
            and failure_key not in emitted
        ):
            alerts.append(
                Alert(
                    rule="repeated_failed_logins",
                    severity="medium",
                    timestamp=event.timestamp,
                    ip=event.ip,
                    description=(
                        f"{len(ip_failures)} failed login attempts "
                        f"within {window_seconds} seconds."
                    ),
                )
            )
            emitted.add(failure_key)

        usernames = {item.username for item in ip_failures}
        username_key = ("multiple_usernames_targeted", event.ip)

        if (
            len(usernames) >= username_threshold
            and username_key not in emitted
        ):
            alerts.append(
                Alert(
                    rule="multiple_usernames_targeted",
                    severity="medium",
                    timestamp=event.timestamp,
                    ip=event.ip,
                    description=(
                        f"Failed logins targeting {len(usernames)} "
                        f"distinct usernames within {window_seconds} seconds."
                    ),
                )
            )
            emitted.add(username_key)

    return alerts