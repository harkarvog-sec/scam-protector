from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import discord
import pytest

import scam_protector


def make_http_exception():
    response = Mock()
    response.status = 500
    response.reason = "Internal Server Error"

    return discord.HTTPException(
        response,
        "Discord API failure",
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
        side_effect=make_http_exception()
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
async def test_http_exception_during_ban_is_handled(
    monkeypatch,
    configured_server,
    capsys,
):
    member = make_member()

    banned_counter = Mock()

    monkeypatch.setattr(
        scam_protector,
        "increment_banned",
        banned_counter,
    )

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

    await scam_protector.process_risk(
        member,
        100,
        ["Test reason"],
        "pytest",
    )

    member.ban.assert_awaited_once()

    banned_counter.assert_not_called()

    output = capsys.readouterr().out

    assert "Discord error banning" in output
