from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import discord
import pytest

import scam_protector


def make_interaction(guild):
    response = SimpleNamespace(
        send_message=AsyncMock(),
        is_done=Mock(return_value=False),
    )

    return SimpleNamespace(
        guild=guild,
        response=response,
    )


def make_general_channel():
    return SimpleNamespace(
        id=111,
        mention="#general",
    )


def make_guild(
    *,
    manage_channels=True,
    bot_member_present=True,
):
    bot_member = None

    if bot_member_present:
        bot_member = Mock()
        bot_member.guild_permissions = SimpleNamespace(
            manage_channels=manage_channels
        )

    return SimpleNamespace(
        id=123456789,
        name="Test Server",
        me=bot_member,
        default_role=Mock(),
        text_channels=[],
        create_text_channel=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_setup_rejects_dm_use():
    interaction = make_interaction(
        guild=None
    )

    await scam_protector.setup.callback(
        interaction,
        make_general_channel(),
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ This command can only be used inside a server.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_rejects_negative_account_age():
    guild = make_guild()

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        make_general_channel(),
        min_account_age=-1,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ Minimum account age cannot be negative.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_rejects_invalid_threshold_order():
    guild = make_guild()

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        make_general_channel(),
        min_account_age=7,
        monitor_threshold=60,
        alert_threshold=30,
        ban_threshold=80,
    )

    args = interaction.response.send_message.await_args.args

    assert "Monitor < Alert < Ban" in args[0]


@pytest.mark.asyncio
async def test_setup_rejects_missing_bot_member():
    guild = make_guild(
        bot_member_present=False
    )

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        make_general_channel(),
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ I could not determine my server permissions.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_rejects_missing_manage_channels_permission():
    guild = make_guild(
        manage_channels=False
    )

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        make_general_channel(),
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ I need **Manage Channels** permission "
        "to create the security channels.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_creates_security_channels_and_saves_config(
    monkeypatch,
):
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    log_channel = SimpleNamespace(
        id=222,
        mention="#scam-logs",
    )

    alert_channel = SimpleNamespace(
        id=333,
        mention="#security-alerts",
    )

    guild.create_text_channel = AsyncMock(
        side_effect=[
            log_channel,
            alert_channel,
        ]
    )

    interaction = make_interaction(guild)

    save_config_mock = Mock()

    monkeypatch.setattr(
        scam_protector,
        "save_server_config",
        save_config_mock,
    )

    await scam_protector.setup.callback(
        interaction,
        general_channel,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    assert guild.create_text_channel.await_count == 2

    save_config_mock.assert_called_once_with(
        guild_id=guild.id,
        log_channel_id=222,
        alert_channel_id=333,
        general_channel_id=111,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    interaction.response.send_message.assert_awaited_once()

    kwargs = (
        interaction
        .response
        .send_message
        .await_args
        .kwargs
    )

    assert kwargs["ephemeral"] is True

    embed = kwargs["embed"]

    assert (
        embed.title
        == "🛡️ Scam Protector Configured"
    )

def make_forbidden():
    response = Mock()
    response.status = 403
    response.reason = "Forbidden"

    return discord.Forbidden(
        response,
        "Missing Permissions",
    )


@pytest.mark.asyncio
async def test_setup_handles_scam_logs_creation_forbidden():
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    guild.create_text_channel = AsyncMock(
        side_effect=make_forbidden()
    )

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        general_channel,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ I don't have permission to create "
        "`#scam-logs`.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_handles_existing_scam_logs_permission_failure():
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    log_channel = SimpleNamespace(
        id=222,
        name="scam-logs",
        mention="#scam-logs",
        set_permissions=AsyncMock(
            side_effect=make_forbidden()
        ),
    )

    guild.text_channels = [
        log_channel
    ]

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        general_channel,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ I cannot configure permissions for "
        "`#scam-logs`.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_handles_security_alert_creation_forbidden():
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    log_channel = SimpleNamespace(
        id=222,
        name="scam-logs",
        mention="#scam-logs",
    )

    guild.create_text_channel = AsyncMock(
        side_effect=[
            log_channel,
            make_forbidden(),
        ]
    )

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        general_channel,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ I don't have permission to create "
        "`#security-alerts`.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_handles_existing_security_alert_permission_failure():
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    log_channel = SimpleNamespace(
        id=222,
        name="scam-logs",
        mention="#scam-logs",
        set_permissions=AsyncMock(),
    )

    alert_channel = SimpleNamespace(
        id=333,
        name="security-alerts",
        mention="#security-alerts",
        set_permissions=AsyncMock(
            side_effect=make_forbidden()
        ),
    )

    guild.text_channels = [
        log_channel,
        alert_channel,
    ]

    interaction = make_interaction(guild)

    await scam_protector.setup.callback(
        interaction,
        general_channel,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ I cannot configure permissions for "
        "`#security-alerts`.",
        ephemeral=True,
    )

@pytest.mark.asyncio
async def test_setup_handles_scam_logs_creation_http_exception(
    monkeypatch,
    capsys,
):
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    response = Mock()
    response.status = 500
    response.reason = "Internal Server Error"

    http_error = discord.HTTPException(
        response,
        "Discord API failure",
    )

    guild.create_text_channel = AsyncMock(
        side_effect=http_error
    )

    interaction = make_interaction(guild)

    save_config_mock = Mock()

    monkeypatch.setattr(
        scam_protector,
        "save_server_config",
        save_config_mock,
    )

    await scam_protector.setup.callback(
        interaction,
        general_channel,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ Discord failed to create `#scam-logs`.",
        ephemeral=True,
    )

    save_config_mock.assert_not_called()

    output = capsys.readouterr().out

    assert "Error creating scam-logs:" in output


@pytest.mark.asyncio
async def test_setup_handles_security_alert_creation_http_exception(
    monkeypatch,
    capsys,
):
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    log_channel = SimpleNamespace(
        id=222,
        mention="#scam-logs",
    )

    response = Mock()
    response.status = 500
    response.reason = "Internal Server Error"

    http_error = discord.HTTPException(
        response,
        "Discord API failure",
    )

    guild.create_text_channel = AsyncMock(
        side_effect=[
            log_channel,
            http_error,
        ]
    )

    interaction = make_interaction(guild)

    save_config_mock = Mock()

    monkeypatch.setattr(
        scam_protector,
        "save_server_config",
        save_config_mock,
    )

    await scam_protector.setup.callback(
        interaction,
        general_channel,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ Discord failed to create "
        "`#security-alerts`.",
        ephemeral=True,
    )

    save_config_mock.assert_not_called()

    output = capsys.readouterr().out

    assert "Error creating security-alerts:" in output

@pytest.mark.asyncio
async def test_setup_configures_existing_security_alert_channel(
    monkeypatch,
):
    guild = make_guild(
        manage_channels=True
    )

    general_channel = make_general_channel()

    log_channel = SimpleNamespace(
        id=222,
        name="scam-logs",
        mention="#scam-logs",
        set_permissions=AsyncMock(),
    )

    alert_channel = SimpleNamespace(
        id=333,
        name="security-alerts",
        mention="#security-alerts",
        set_permissions=AsyncMock(),
    )

    guild.text_channels = [
        log_channel,
        alert_channel,
    ]

    interaction = make_interaction(guild)

    save_config_mock = Mock()

    monkeypatch.setattr(
        scam_protector,
        "save_server_config",
        save_config_mock,
    )

    await scam_protector.setup.callback(
        interaction,
        general_channel,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    assert alert_channel.set_permissions.await_count == 2

    save_config_mock.assert_called_once_with(
        guild_id=guild.id,
        log_channel_id=222,
        alert_channel_id=333,
        general_channel_id=111,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )
