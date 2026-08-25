from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import scam_protector


def make_member():
    """
    Create a fake Discord member and guild for testing
    process_risk() without connecting to Discord.
    """

    guild = SimpleNamespace(
        id=123456789,
        name="Test Server",
    )

    member = SimpleNamespace(
        id=987654321,
        guild=guild,
        display_avatar=SimpleNamespace(
            url="https://example.com/avatar.png"
        ),
    )

    member.ban = AsyncMock()

    return member


@pytest.fixture
def configured_server(monkeypatch):
    """
    Provide the standard Scam Protector thresholds
    without accessing the real SQLite database.
    """

    config = {
        "monitor_threshold": 30,
        "alert_threshold": 60,
        "ban_threshold": 80,
    }

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: config,
    )

    return config


@pytest.mark.asyncio
async def test_score_29_takes_no_action(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    await scam_protector.process_risk(
        member,
        29,
        ["Test reason"],
        "pytest",
    )

    log_mock.assert_not_awaited()
    alert_mock.assert_not_awaited()
    member.ban.assert_not_awaited()


@pytest.mark.asyncio
async def test_score_30_enters_monitoring(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    await scam_protector.process_risk(
        member,
        30,
        ["Test reason"],
        "pytest",
    )

    log_mock.assert_awaited_once()
    alert_mock.assert_not_awaited()
    member.ban.assert_not_awaited()


@pytest.mark.asyncio
async def test_score_59_remains_monitoring(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    await scam_protector.process_risk(
        member,
        59,
        ["Test reason"],
        "pytest",
    )

    log_mock.assert_awaited_once()
    alert_mock.assert_not_awaited()
    member.ban.assert_not_awaited()


@pytest.mark.asyncio
async def test_score_60_triggers_admin_alert(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "increment_alerts",
        Mock(),
    )

    await scam_protector.process_risk(
        member,
        60,
        ["Test reason"],
        "pytest",
    )

    log_mock.assert_awaited_once()
    alert_mock.assert_awaited_once()
    member.ban.assert_not_awaited()


@pytest.mark.asyncio
async def test_score_79_triggers_alert_but_not_ban(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "increment_alerts",
        Mock(),
    )

    await scam_protector.process_risk(
        member,
        79,
        ["Test reason"],
        "pytest",
    )

    log_mock.assert_awaited_once()
    alert_mock.assert_awaited_once()
    member.ban.assert_not_awaited()


@pytest.mark.asyncio
async def test_score_80_triggers_automatic_ban(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()
    banned_counter = Mock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "increment_banned",
        banned_counter,
    )

    await scam_protector.process_risk(
        member,
        80,
        ["Test reason"],
        "pytest",
    )

    member.ban.assert_awaited_once()

    banned_counter.assert_called_once_with(
        member.guild.id
    )

    log_mock.assert_awaited_once()
    alert_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_score_above_80_triggers_automatic_ban(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "increment_banned",
        Mock(),
    )

    await scam_protector.process_risk(
        member,
        100,
        ["Test reason"],
        "pytest",
    )

    member.ban.assert_awaited_once()
    log_mock.assert_awaited_once()
    alert_mock.assert_awaited_once()

@pytest.mark.asyncio
async def test_process_risk_returns_when_server_not_configured(
    monkeypatch,
):
    member = make_member()

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    log_mock = AsyncMock()
    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        alert_mock,
    )

    await scam_protector.process_risk(
        member,
        100,
        ["Test reason"],
        "pytest",
    )

    member.ban.assert_not_awaited()
    log_mock.assert_not_awaited()
    alert_mock.assert_not_awaited()
