from datetime import datetime, timezone

import pytest

from loginwatch.parser import LogParseError
from loginwatch.ssh_parser import load_ssh


def write_log(tmp_path, content):
    path = tmp_path / "auth.log"
    path.write_text(content, encoding="utf-8")
    return path


def test_reads_failed_login_for_invalid_user(tmp_path):
    path = write_log(
        tmp_path,
        "Oct 21 10:02:00 server sshd[1001]: "
        "Failed password for invalid user admin "
        "from 192.0.2.10 port 50200 ssh2\n",
    )

    events = load_ssh(path, year=2026)

    assert len(events) == 1
    assert events[0].username == "admin"
    assert events[0].ip == "192.0.2.10"
    assert events[0].success is False
    assert events[0].timestamp == datetime(
        2026, 10, 21, 10, 2, tzinfo=timezone.utc
    )


def test_reads_iso_timestamp_and_ipv6(tmp_path):
    path = write_log(
        tmp_path,
        "2026-10-21T13:00:00+03:00 server sshd[1002]: "
        "Accepted publickey for alice "
        "from 2001:db8::1 port 50201 ssh2\n",
    )

    events = load_ssh(path)

    assert events[0].success is True
    assert events[0].ip == "2001:db8::1"
    assert events[0].timestamp == datetime(
        2026, 10, 21, 10, 0, tzinfo=timezone.utc
    )


def test_traditional_timestamp_requires_year(tmp_path):
    path = write_log(
        tmp_path,
        "Oct 21 10:02:00 server sshd[1001]: "
        "Failed password for admin from 192.0.2.10 port 50200 ssh2\n",
    )

    with pytest.raises(LogParseError, match="--year"):
        load_ssh(path)


def test_ignores_unrelated_messages(tmp_path):
    path = write_log(
        tmp_path,
        "Oct 21 10:00:00 server sshd[1000]: "
        "pam_unix(sshd:session): session opened for user alice\n"
        "Oct 21 10:01:00 server sshd[1001]: "
        "Accepted password for alice "
        "from 198.51.100.25 port 50200 ssh2\n",
    )

    events = load_ssh(path, year=2026)

    assert len(events) == 1
    assert events[0].success is True


def test_rejects_invalid_ip(tmp_path):
    path = write_log(
        tmp_path,
        "Oct 21 10:02:00 server sshd[1001]: "
        "Failed password for admin from 999.1.1.1 port 50200 ssh2\n",
    )

    with pytest.raises(LogParseError, match="invalid IP"):
        load_ssh(path, year=2026)


def test_rejects_file_without_supported_events(tmp_path):
    path = write_log(tmp_path, "This is not an SSH authentication event.\n")

    with pytest.raises(LogParseError, match="No supported SSH login events"):
        load_ssh(path)


def test_sorts_events_by_time(tmp_path):
    path = write_log(
        tmp_path,
        "Oct 21 10:05:00 server sshd[1002]: "
        "Accepted password for alice "
        "from 198.51.100.25 port 50201 ssh2\n"
        "Oct 21 10:00:00 server sshd[1001]: "
        "Failed password for alice "
        "from 198.51.100.25 port 50200 ssh2\n",
    )

    events = load_ssh(path, year=2026)

    assert events[0].success is False
    assert events[1].success is True
    assert events[0].timestamp < events[1].timestamp