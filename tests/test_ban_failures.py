from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import discord
import pytest

import scam_protector


def make_forbidden():
    response = Mock()
    response.status = 403
    response.reason = "Forbidden"

    return discord.Forbidden(
        response,
        "Missing Permissions",
    )


def make_member():
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

    member.ban = AsyncMock(
        side_effect=make_forbidden()
    )

    return member


@pytest.fixture
def configured_server(monkeypatch):
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


@pytest.mark.asyncio
async def test_failed_ban_is_logged_and_alerted(
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
        100,
        ["Test suspicious activity"],
        "pytest",
    )

    member.ban.assert_awaited_once()

    log_mock.assert_awaited_once()
    alert_mock.assert_awaited_once()

    # A failed ban must NOT be counted as a successful ban.
    banned_counter.assert_not_called()


@pytest.mark.asyncio
async def test_failed_ban_does_not_crash_process_risk(
    monkeypatch,
    configured_server,
):
    member = make_member()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        AsyncMock(),
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        AsyncMock(),
    )

    monkeypatch.setattr(
        scam_protector,
        "increment_banned",
        Mock(),
    )

    # If discord.Forbidden escapes process_risk(),
    # pytest will fail this test automatically.
    await scam_protector.process_risk(
        member,
        80,
        ["Test reason"],
        "pytest",
    )


@pytest.mark.asyncio
async def test_failed_ban_embed_has_expected_title(
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

    # send_security_log(guild, embed)
    args = log_mock.await_args.args

    embed = args[1]

    assert embed.title == "⚠️ BAN FAILED"


@pytest.mark.asyncio
async def test_failed_ban_alert_contains_risk_score(
    monkeypatch,
    configured_server,
):
    member = make_member()

    alert_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        AsyncMock(),
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

    args = alert_mock.await_args.args

    embed = args[1]

    fields = {
        field.name: field.value
        for field in embed.fields
    }

    assert fields["Risk Score"] == "100"


@pytest.mark.asyncio
async def test_failed_ban_reason_explains_permission_problem(
    monkeypatch,
    configured_server,
):
    member = make_member()

    log_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "send_security_log",
        log_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_security_alert",
        AsyncMock(),
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

    args = log_mock.await_args.args

    embed = args[1]

    fields = {
        field.name: field.value
        for field in embed.fields
    }

    assert (
        "Ban Members permission"
        in fields["Reason"]
    )
