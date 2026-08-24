import datetime
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


def make_user():
    created_at = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=100)
    )

    return SimpleNamespace(
        id=987654321,
        created_at=created_at,
        display_avatar=SimpleNamespace(
            url="https://example.com/avatar.png"
        ),
    )


def get_embed_field(embed, field_name):
    """
    Return the value of an embed field by name.
    """

    for field in embed.fields:
        if field.name == field_name:
            return field.value

    raise AssertionError(
        f"Embed field not found: {field_name}"
    )


# ============================================================
# SERVER / CONFIGURATION CHECKS
# ============================================================

@pytest.mark.asyncio
async def test_check_rejects_dm_use():
    interaction = make_interaction(
        guild=None
    )

    user = make_user()

    await scam_protector.check.callback(
        interaction,
        user,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ This command can only be used inside a server.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_check_rejects_unconfigured_server(
    monkeypatch,
):
    guild = make_guild()

    interaction = make_interaction(guild)

    user = make_user()

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: None,
    )

    await scam_protector.check.callback(
        interaction,
        user,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "⚠️ This server has not been configured.\n"
        "Use `/setup` first.",
        ephemeral=True,
    )


# ============================================================
# CLASSIFICATION HELPER
# ============================================================

async def run_classification_test(
    monkeypatch,
    *,
    stored_score,
    current_scan,
):
    guild = make_guild()

    interaction = make_interaction(guild)

    user = make_user()

    settings = {
        "min_account_age": 7,
        "monitor_threshold": 30,
        "alert_threshold": 60,
        "ban_threshold": 80,
    }

    monkeypatch.setattr(
        scam_protector,
        "get_server_config",
        lambda guild_id: settings,
    )

    monkeypatch.setattr(
        scam_protector,
        "get_user_score",
        lambda guild_id, user_id: stored_score,
    )

    monkeypatch.setattr(
        scam_protector,
        "initial_scan",
        lambda user, minimum_age: (
            current_scan,
            [],
        ),
    )

    monkeypatch.setattr(
        scam_protector,
        "get_account_age",
        lambda user: datetime.timedelta(
            days=100
        ),
    )

    await scam_protector.check.callback(
        interaction,
        user,
    )

    interaction.response.send_message.assert_awaited_once()

    kwargs = (
        interaction
        .response
        .send_message
        .await_args
        .kwargs
    )

    return kwargs["embed"]


# ============================================================
# RISK CLASSIFICATION TESTS
# ============================================================

@pytest.mark.asyncio
async def test_check_classifies_low_risk(
    monkeypatch,
):
    embed = await run_classification_test(
        monkeypatch,
        stored_score=0,
        current_scan=0,
    )

    assert (
        get_embed_field(
            embed,
            "Result",
        )
        == "🟢 LOW RISK"
    )


@pytest.mark.asyncio
async def test_check_classifies_monitor(
    monkeypatch,
):
    embed = await run_classification_test(
        monkeypatch,
        stored_score=30,
        current_scan=0,
    )

    assert (
        get_embed_field(
            embed,
            "Result",
        )
        == "🟡 MONITOR"
    )


@pytest.mark.asyncio
async def test_check_classifies_suspicious(
    monkeypatch,
):
    embed = await run_classification_test(
        monkeypatch,
        stored_score=60,
        current_scan=0,
    )

    assert (
        get_embed_field(
            embed,
            "Result",
        )
        == "🟠 SUSPICIOUS"
    )


@pytest.mark.asyncio
async def test_check_classifies_high_risk(
    monkeypatch,
):
    embed = await run_classification_test(
        monkeypatch,
        stored_score=80,
        current_scan=0,
    )

    assert (
        get_embed_field(
            embed,
            "Result",
        )
        == "🚨 HIGH RISK"
    )


# ============================================================
# SCORE CALCULATION
# ============================================================

@pytest.mark.asyncio
async def test_check_uses_higher_current_scan_score(
    monkeypatch,
):
    embed = await run_classification_test(
        monkeypatch,
        stored_score=20,
        current_scan=60,
    )

    assert (
        get_embed_field(
            embed,
            "Stored Risk Score",
        )
        == "20"
    )

    assert (
        get_embed_field(
            embed,
            "Current Risk",
        )
        == "60"
    )

    assert (
        get_embed_field(
            embed,
            "Result",
        )
        == "🟠 SUSPICIOUS"
    )


@pytest.mark.asyncio
async def test_check_keeps_higher_stored_score(
    monkeypatch,
):
    embed = await run_classification_test(
        monkeypatch,
        stored_score=80,
        current_scan=20,
    )

    assert (
        get_embed_field(
            embed,
            "Current Risk",
        )
        == "80"
    )

    assert (
        get_embed_field(
            embed,
            "Result",
        )
        == "🚨 HIGH RISK"
    )
