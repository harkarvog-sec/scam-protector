import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import scam_protector


def make_member():
    guild = SimpleNamespace(
        id=123456789,
        name="Test Server",
    )

    return SimpleNamespace(
        id=987654321,
        guild=guild,
        mention="<@987654321>",
        display_avatar=SimpleNamespace(
            url="https://example.com/avatar.png"
        ),
    )


def make_message(
    *,
    author_bot=False,
    guild=True,
):
    author = SimpleNamespace(
        id=987654321,
        bot=author_bot,
        guild=SimpleNamespace(
            id=123456789,
            name="Test Server",
        ),
    )

    message_guild = (
        SimpleNamespace(
            id=123456789,
            name="Test Server",
        )
        if guild
        else None
    )

    return SimpleNamespace(
        author=author,
        guild=message_guild,
        content="Hello",
        mentions=[],
        mention_everyone=False,
    )


# ============================================================
# NEW MEMBER EVENT
# ============================================================

@pytest.mark.asyncio
async def test_unconfigured_server_skips_new_member_scan(
    monkeypatch,
):
    member = make_member()

    initial_scan_mock = Mock()
    add_score_mock = Mock()
    general_mock = AsyncMock()
    process_risk_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    monkeypatch.setattr(
        scam_protector,
        "initial_scan",
        initial_scan_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "add_user_score",
        add_score_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "send_general_notification",
        general_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "process_risk",
        process_risk_mock,
    )

    await scam_protector.on_member_join(member)

    initial_scan_mock.assert_not_called()
    add_score_mock.assert_not_called()
    general_mock.assert_not_awaited()
    process_risk_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_new_member_is_scanned_and_processed(
    monkeypatch,
):
    member = make_member()

    config = {
        "min_account_age": 7,
    }

    reasons = [
        "Account age risk: +40"
    ]

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: config,
    )

    initial_scan_mock = Mock(
        return_value=(
            40,
            reasons,
        )
    )

    add_score_mock = Mock(
        return_value=40
    )

    general_mock = AsyncMock()
    process_risk_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "initial_scan",
        initial_scan_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "add_user_score",
        add_score_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "get_account_age",
        lambda member: datetime.timedelta(
            days=2
        ),
    )

    monkeypatch.setattr(
        scam_protector,
        "send_general_notification",
        general_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "process_risk",
        process_risk_mock,
    )

    await scam_protector.on_member_join(member)

    initial_scan_mock.assert_called_once_with(
        member,
        7,
    )

    add_score_mock.assert_called_once_with(
        member.guild.id,
        member.id,
        40,
    )

    general_mock.assert_awaited_once()

    process_risk_mock.assert_awaited_once_with(
        member,
        40,
        reasons,
        "New Member Scan",
    )


# ============================================================
# MESSAGE EVENT
# ============================================================

@pytest.mark.asyncio
async def test_bot_message_is_ignored(
    monkeypatch,
):
    message = make_message(
        author_bot=True
    )

    process_commands_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector.bot,
        "process_commands",
        process_commands_mock,
    )

    await scam_protector.on_message(message)

    process_commands_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_direct_message_is_passed_to_commands(
    monkeypatch,
):
    message = make_message(
        guild=False
    )

    process_commands_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector.bot,
        "process_commands",
        process_commands_mock,
    )

    await scam_protector.on_message(message)

    process_commands_mock.assert_awaited_once_with(
        message
    )


@pytest.mark.asyncio
async def test_unconfigured_server_message_skips_risk_scan(
    monkeypatch,
):
    message = make_message()

    process_commands_mock = AsyncMock()
    message_score_mock = Mock()

    monkeypatch.setattr(
        scam_protector.bot,
        "process_commands",
        process_commands_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    monkeypatch.setattr(
        scam_protector,
        "message_score",
        message_score_mock,
    )

    await scam_protector.on_message(message)

    message_score_mock.assert_not_called()

    process_commands_mock.assert_awaited_once_with(
        message
    )


@pytest.mark.asyncio
async def test_safe_message_does_not_add_risk(
    monkeypatch,
):
    message = make_message()

    add_score_mock = Mock()
    process_risk_mock = AsyncMock()
    process_commands_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "monitor_threshold": 30,
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "message_score",
        lambda message: (
            0,
            [],
        ),
    )

    monkeypatch.setattr(
        scam_protector,
        "add_user_score",
        add_score_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "process_risk",
        process_risk_mock,
    )

    monkeypatch.setattr(
        scam_protector.bot,
        "process_commands",
        process_commands_mock,
    )

    await scam_protector.on_message(message)

    add_score_mock.assert_not_called()
    process_risk_mock.assert_not_awaited()

    process_commands_mock.assert_awaited_once_with(
        message
    )


@pytest.mark.asyncio
async def test_risky_message_adds_score_and_processes_risk(
    monkeypatch,
):
    message = make_message()

    reasons = [
        "Suspicious phrase detected: +30"
    ]

    add_score_mock = Mock(
        return_value=70
    )

    process_risk_mock = AsyncMock()
    process_commands_mock = AsyncMock()

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: {
            "monitor_threshold": 30,
        },
    )

    monkeypatch.setattr(
        scam_protector,
        "message_score",
        lambda message: (
            30,
            reasons,
        ),
    )

    monkeypatch.setattr(
        scam_protector,
        "add_user_score",
        add_score_mock,
    )

    monkeypatch.setattr(
        scam_protector,
        "process_risk",
        process_risk_mock,
    )

    monkeypatch.setattr(
        scam_protector.bot,
        "process_commands",
        process_commands_mock,
    )

    await scam_protector.on_message(message)

    add_score_mock.assert_called_once_with(
        message.guild.id,
        message.author.id,
        30,
    )

    process_risk_mock.assert_awaited_once_with(
        message.author,
        70,
        reasons,
        "Message Activity",
    )

    process_commands_mock.assert_awaited_once_with(
        message
    )
