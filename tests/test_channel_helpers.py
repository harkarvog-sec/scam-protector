from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import discord
import pytest

import scam_protector


def make_guild():
    return SimpleNamespace(
        id=123456789,
        name="Test Server",
        get_channel=Mock(),
    )


def make_forbidden():
    response = Mock()
    response.status = 403
    response.reason = "Forbidden"

    return discord.Forbidden(
        response,
        "Missing Permissions",
    )


def make_not_found():
    response = Mock()
    response.status = 404
    response.reason = "Not Found"

    return discord.NotFound(
        response,
        "Channel not found",
    )


# ============================================================
# GET CHANNEL
# ============================================================

@pytest.mark.asyncio
async def test_get_channel_returns_none_for_missing_channel_id():
    guild = make_guild()

    result = await scam_protector.get_channel(
        guild,
        None,
    )

    assert result is None

    guild.get_channel.assert_not_called()


@pytest.mark.asyncio
async def test_get_channel_returns_cached_guild_channel(
    monkeypatch,
):
    guild = make_guild()

    channel = object()

    guild.get_channel.return_value = channel

    fetch_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector.bot,
        "fetch_channel",
        fetch_mock,
    )

    result = await scam_protector.get_channel(
        guild,
        100,
    )

    assert result is channel

    guild.get_channel.assert_called_once_with(100)
    fetch_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_channel_fetches_channel_when_not_cached(
    monkeypatch,
):
    guild = make_guild()

    guild.get_channel.return_value = None

    fetched_channel = object()

    fetch_mock = AsyncMock(
        return_value=fetched_channel
    )

    monkeypatch.setattr(
        scam_protector.bot,
        "fetch_channel",
        fetch_mock,
    )

    result = await scam_protector.get_channel(
        guild,
        200,
    )

    assert result is fetched_channel

    guild.get_channel.assert_called_once_with(200)
    fetch_mock.assert_awaited_once_with(200)


@pytest.mark.asyncio
async def test_get_channel_returns_none_when_channel_not_found(
    monkeypatch,
):
    guild = make_guild()

    guild.get_channel.return_value = None

    fetch_mock = AsyncMock(
        side_effect=make_not_found()
    )

    monkeypatch.setattr(
        scam_protector.bot,
        "fetch_channel",
        fetch_mock,
    )

    result = await scam_protector.get_channel(
        guild,
        999,
    )

    assert result is None


# ============================================================
# SECURITY LOG
# ============================================================

@pytest.mark.asyncio
async def test_security_log_does_nothing_without_config(
    monkeypatch,
):
    guild = make_guild()

    get_channel_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    monkeypatch.setattr(
        scam_protector,
        "get_channel",
        get_channel_mock,
    )

    await scam_protector.send_security_log(
        guild,
        object(),
    )

    get_channel_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_security_log_sends_embed(
    monkeypatch,
):
    guild = make_guild()

    embed = object()

    channel = SimpleNamespace(
        send=AsyncMock()
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "log_channel_id": 10
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "get_channel",
        AsyncMock(return_value=channel),
    )

    await scam_protector.send_security_log(
        guild,
        embed,
    )

    channel.send.assert_awaited_once_with(
        embed=embed
    )


@pytest.mark.asyncio
async def test_security_log_handles_forbidden(
    monkeypatch,
):
    guild = make_guild()

    channel = SimpleNamespace(
        send=AsyncMock(
            side_effect=make_forbidden()
        )
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "log_channel_id": 10
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "get_channel",
        AsyncMock(return_value=channel),
    )

    # The important test:
    # Forbidden must be handled instead of escaping.
    await scam_protector.send_security_log(
        guild,
        object(),
    )

    channel.send.assert_awaited_once()


# ============================================================
# GENERAL NOTIFICATION
# ============================================================

@pytest.mark.asyncio
async def test_general_notification_sends_embed(
    monkeypatch,
):
    guild = make_guild()

    embed = object()

    channel = SimpleNamespace(
        send=AsyncMock()
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "general_channel_id": 20
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "get_channel",
        AsyncMock(return_value=channel),
    )

    await scam_protector.send_general_notification(
        guild,
        embed,
    )

    channel.send.assert_awaited_once_with(
        embed=embed
    )


# ============================================================
# SECURITY ALERT
# ============================================================

@pytest.mark.asyncio
async def test_security_alert_sends_embed(
    monkeypatch,
):
    guild = make_guild()

    embed = object()

    channel = SimpleNamespace(
        send=AsyncMock()
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "alert_channel_id": 30
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "get_channel",
        AsyncMock(return_value=channel),
    )

    await scam_protector.send_security_alert(
        guild,
        embed,
    )

    channel.send.assert_awaited_once_with(
        embed=embed
    )


@pytest.mark.asyncio
async def test_security_alert_handles_forbidden(
    monkeypatch,
):
    guild = make_guild()

    channel = SimpleNamespace(
        send=AsyncMock(
            side_effect=make_forbidden()
        )
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "alert_channel_id": 30
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "get_channel",
        AsyncMock(return_value=channel),
    )

    await scam_protector.send_security_alert(
        guild,
        object(),
    )

    channel.send.assert_awaited_once()
