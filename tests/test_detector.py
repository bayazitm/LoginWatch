from datetime import datetime, timedelta, timezone

from loginwatch.detector import detect
from loginwatch.parser import LoginEvent


BASE_TIME = datetime(2026, 10, 21, 10, 0, tzinfo=timezone.utc)


def event(seconds, username="admin", success=False, ip="192.0.2.10"):
    return LoginEvent(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        ip=ip,
        username=username,
        success=success,
        line_number=2,
    )


def rules(events, **settings):
    return [alert.rule for alert in detect(events, **settings)]


def test_normal_activity_does_not_trigger_alerts():
    events = [
        event(0, success=True),
        event(10, username="alice"),
        event(20, username="alice", success=True),
    ]

    assert detect(events) == []


def test_five_failures_trigger_one_alert():
    events = [event(second) for second in range(10)]

    assert rules(events) == ["repeated_failed_logins"]


def test_old_failures_are_excluded_from_window():
    events = [event(second) for second in (0, 301, 602, 903, 1204)]

    assert detect(events) == []


def test_window_includes_exact_boundary():
    events = [event(second) for second in (0, 75, 150, 225, 300)]

    assert rules(events) == ["repeated_failed_logins"]


def test_distinct_usernames_trigger_alert():
    events = [
        event(0, username="admin"),
        event(10, username="root"),
        event(20, username="guest"),
    ]

    assert rules(events) == ["multiple_usernames_targeted"]


def test_success_after_three_failures_triggers_high_alert():
    events = [
        event(0),
        event(10),
        event(20),
        event(30, success=True),
    ]

    alerts = detect(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "success_after_failures"
    assert alerts[0].severity == "high"


def test_failures_for_other_users_do_not_trigger_success_alert():
    events = [
        event(0, username="admin"),
        event(10, username="admin"),
        event(20, username="admin"),
        event(30, username="alice", success=True),
    ]

    assert detect(events) == []


def test_failures_from_different_ips_are_not_combined():
    events = [
        event(0, ip="192.0.2.10"),
        event(10, ip="192.0.2.10"),
        event(20, ip="192.0.2.10"),
        event(30, ip="192.0.2.20"),
        event(40, ip="192.0.2.20"),
    ]

    assert detect(events) == []


def test_success_resets_account_failure_sequence():
    events = [
        event(0),
        event(10),
        event(20),
        event(30, success=True),
        event(40, success=True),
    ]

    assert rules(events) == ["success_after_failures"]


def test_unsorted_events_are_processed_chronologically():
    events = [
        event(30, success=True),
        event(20),
        event(0),
        event(10),
    ]

    assert rules(events) == ["success_after_failures"]