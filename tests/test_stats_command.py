import sqlite3
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


def make_guild():
    return SimpleNamespace(
        id=123456789,
        name="Test Server",
    )


def make_settings():
    return {
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


def prepare_database(tmp_path, monkeypatch):
    db_file = tmp_path / "stats_test.db"

    def test_get_db():
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row
        return conn

    monkeypatch.setattr(
        scam_protector,
        "get_db",
        test_get_db,
    )

    scam_protector.setup_database()

    return test_get_db


@pytest.mark.asyncio
async def test_stats_rejects_dm_use():
    interaction = make_interaction(
        guild=None
    )

    await scam_protector.stats.callback(
        interaction
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ This command can only be used inside a server.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_stats_rejects_unconfigured_server(
    monkeypatch,
):
    guild = make_guild()

    interaction = make_interaction(guild)

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    await scam_protector.stats.callback(
        interaction
    )

    interaction.response.send_message.assert_awaited_once_with(
        "⚠️ This server has not been configured.\n"
        "Use `/setup` first.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_stats_displays_server_statistics(
    tmp_path,
    monkeypatch,
):
    guild = make_guild()

    interaction = make_interaction(guild)

    test_get_db = prepare_database(
        tmp_path,
        monkeypatch,
    )

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: make_settings(),
    )

    conn = test_get_db()

    conn.execute(
        """
        INSERT INTO user_risk
        (guild_id, user_id, score)
        VALUES (?, ?, ?)
        """,
        (
            guild.id,
            1001,
            40,
        ),
    )

    conn.execute(
        """
        INSERT INTO user_risk
        (guild_id, user_id, score)
        VALUES (?, ?, ?)
        """,
        (
            guild.id,
            1002,
            70,
        ),
    )

    conn.execute(
        """
        INSERT INTO statistics
        (guild_id, banned, alerts)
        VALUES (?, ?, ?)
        """,
        (
            guild.id,
            3,
            5,
        ),
    )

    conn.commit()
    conn.close()

    await scam_protector.stats.callback(
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
        "Server"
    ) == "Test Server"

    assert get_embed_field(
        embed,
        "Users Monitored"
    ) == "2"

    assert get_embed_field(
        embed,
        "Accounts Banned"
    ) == "3"

    assert get_embed_field(
        embed,
        "Security Alerts"
    ) == "5"

    assert get_embed_field(
        embed,
        "Monitor Threshold"
    ) == "30"

    assert get_embed_field(
        embed,
        "Alert Threshold"
    ) == "60"

    assert get_embed_field(
        embed,
        "Ban Threshold"
    ) == "80"

    assert get_embed_field(
        embed,
        "Status"
    ) == "🟢 Online & Active"
