from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from discord import app_commands
import pytest

import scam_protector


def make_interaction(*, response_done=False):
    return SimpleNamespace(
        response=SimpleNamespace(
            send_message=AsyncMock(),
            is_done=Mock(
                return_value=response_done
            ),
        )
    )


@pytest.mark.asyncio
async def test_setup_error_handles_missing_permissions():
    interaction = make_interaction()

    error = app_commands.errors.MissingPermissions(
        ["manage_guild"]
    )

    await scam_protector.setup_error(
        interaction,
        error,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ You need **Manage Server** permission "
        "to configure Scam Protector.",
        ephemeral=True,
    )


@pytest.mark.asyncio
async def test_setup_error_handles_unexpected_error(
    capsys,
):
    interaction = make_interaction(
        response_done=False
    )

    error = RuntimeError(
        "unexpected setup failure"
    )

    await scam_protector.setup_error(
        interaction,
        error,
    )

    interaction.response.send_message.assert_awaited_once_with(
        "❌ An error occurred while configuring "
        "Scam Protector.",
        ephemeral=True,
    )

    output = capsys.readouterr().out

    assert (
        "/setup error: unexpected setup failure"
        in output
    )


@pytest.mark.asyncio
async def test_setup_error_does_not_send_second_response(
    capsys,
):
    interaction = make_interaction(
        response_done=True
    )

    error = RuntimeError(
        "already responded"
    )

    await scam_protector.setup_error(
        interaction,
        error,
    )

    interaction.response.is_done.assert_called_once()

    interaction.response.send_message.assert_not_awaited()

    output = capsys.readouterr().out

    assert (
        "/setup error: already responded"
        in output
    )
