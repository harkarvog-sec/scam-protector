from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import scam_protector


def make_interaction(guild=None):
    return SimpleNamespace(
        guild=guild,
        response=SimpleNamespace(
            send_message=AsyncMock()
        ),
    )


def make_channel(channel_id, mention):
    return SimpleNamespace(
        id=channel_id,
        mention=mention,
    )


def make_guild():
    channels = {
        111: make_channel(111, "#general"),
        222: make_channel(222, "#scam-logs"),
        333: make_channel(333, "#security-alerts"),
    }

    return SimpleNamespace(
        id=123456789,
        name="Test Server",
        get_channel=lambda channel_id: channels.get(channel_id),
    )


def make_settings():
    return {
        "general_channel_id": 111,
        "log_channel_id": 222,
        "alert_channel_id": 333,
        "min_account_age": 7,
        "monitor_threshold": 30,
        "alert_threshold": 60,
        "ban_threshold": 80,
    }


def get_embed_field(embed, field_name):
    for field in embed.fields:
        if field.name == field_name:
            return field.value

    raise AssertionError(
        f"Embed field not found: {field_name}"
    )


@pytest.mark.asyncio
async def test_config_rejects_dm_use():
    interaction = make_interaction(
        guild=None
    )

    await scam_protector.config.callback(
        interaction
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ This command can only be used inside a server.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_config_rejects_unconfigured_server(
    monkeypatch,
):
    guild = make_guild()

    interaction = make_interaction(guild)

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    await scam_protector.config.callback(
        interaction
    )

    interaction.response.send_message.assert_awaited_once_with(
        "⚠️ This server has not been configured.\n"
        "Use `/setup` first.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_config_displays_saved_configuration(
    monkeypatch,
):
    guild = make_guild()

    interaction = make_interaction(guild)

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: make_settings(),
    )

    await scam_protector.config.callback(
        interaction
    )

    interaction.response.send_message.assert_awaited_once()

    kwargs = (
        interaction.response
        .send_message.await_args.kwargs
    )

    embed = kwargs["embed"]

    assert get_embed_field(
        embed,
        "📢 General Channel"
    ) == "#general"

    assert get_embed_field(
        embed,
        "🔒 Security Logs"
    ) == "#scam-logs"

    assert get_embed_field(
        embed,
        "🚨 Security Alerts"
    ) == "#security-alerts"

    assert get_embed_field(
        embed,
        "👤 Minimum Account Age"
    ) == "7 days"

    assert get_embed_field(
        embed,
        "🟡 Monitor Threshold"
    ) == "30"

    assert get_embed_field(
        embed,
        "🟠 Alert Threshold"
    ) == "60"

    assert get_embed_field(
        embed,
        "🔴 Ban Threshold"
    ) == "80"

    assert get_embed_field(
        embed,
        "🟢 Status"
    ) == "Online & Active"

    assert kwargs["ephemeral"] is True


@pytest.mark.asyncio
async def test_config_handles_missing_channels(
    monkeypatch,
):
    guild = SimpleNamespace(
        id=123456789,
        name="Test Server",
        get_channel=lambda channel_id: None,
    )

    interaction = make_interaction(guild)

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: make_settings(),
    )

    await scam_protector.config.callback(
        interaction
    )

    kwargs = (
        interaction.response
        .send_message.await_args.kwargs
    )

    embed = kwargs["embed"]

    assert get_embed_field(
        embed,
        "📢 General Channel"
    ) == "❌ Channel not found"

    assert get_embed_field(
        embed,
        "🔒 Security Logs"
    ) == "❌ Channel not found"

    assert get_embed_field(
        embed,
        "🚨 Security Alerts"
    ) == "❌ Channel not found"
