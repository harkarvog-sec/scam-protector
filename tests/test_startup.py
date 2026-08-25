from types import SimpleNamespace
from unittest.mock import Mock, AsyncMock

import pytest
import runpy
import scam_protector


@pytest.mark.asyncio
async def test_on_ready_syncs_commands(
    monkeypatch,
    capsys,
):
    synced_commands = [
        object(),
        object(),
        object(),
        object(),
    ]

    sync_mock = AsyncMock(
        return_value=synced_commands
    )

    monkeypatch.setattr(
        scam_protector.bot.tree,
        "sync",
        sync_mock,
    )

    fake_connection = SimpleNamespace(
        user="Scam Protector",
        guilds=[
            object(),
            object(),
        ],
    )

    monkeypatch.setattr(
        scam_protector.bot,
        "_connection",
        fake_connection,
    )

    await scam_protector.on_ready()

    sync_mock.assert_awaited_once()

    output = capsys.readouterr().out

    assert "Scam Protector is online!" in output
    assert "Protecting 2 servers." in output
    assert "Synced 4 commands." in output


@pytest.mark.asyncio
async def test_on_ready_handles_sync_failure(
    monkeypatch,
    capsys,
):
    sync_mock = AsyncMock(
        side_effect=RuntimeError(
            "sync failed"
        )
    )

    monkeypatch.setattr(
        scam_protector.bot.tree,
        "sync",
        sync_mock,
    )

    fake_connection = SimpleNamespace(
        user="Scam Protector",
        guilds=[],
    )

    monkeypatch.setattr(
        scam_protector.bot,
        "_connection",
        fake_connection,
    )

    await scam_protector.on_ready()

    sync_mock.assert_awaited_once()

    output = capsys.readouterr().out

    assert "Scam Protector is online!" in output
    assert "Protecting 0 servers." in output
    assert "Command sync error: sync failed" in output


def test_main_raises_when_token_missing(
    monkeypatch,
):
    monkeypatch.setattr(
        scam_protector,
        "TOKEN",
        None,
    )

    run_mock = Mock()

    monkeypatch.setattr(
        scam_protector.bot,
        "run",
        run_mock,
    )

    with pytest.raises(
        RuntimeError,
        match="DISCORD_TOKEN is not set",
    ):
        scam_protector.main()

    run_mock.assert_not_called()


def test_main_runs_bot_when_token_exists(
    monkeypatch,
):
    token = "test-token"

    monkeypatch.setattr(
        scam_protector,
        "TOKEN",
        token,
    )

    run_mock = Mock()

    monkeypatch.setattr(
        scam_protector.bot,
        "run",
        run_mock,
    )

    scam_protector.main()

    run_mock.assert_called_once_with(
        token
    )

def test_module_main_guard_executes(
    monkeypatch,
    tmp_path,
):
    """
    Execute scam_protector.py as __main__.

    The Discord token is deliberately removed so main()
    raises before attempting a real Discord connection.
    """

    module_path = scam_protector.__file__

    monkeypatch.delenv(
        "DISCORD_TOKEN",
        raising=False,
    )

    # Keep the database created by the second module
    # execution inside pytest's temporary directory.
    monkeypatch.chdir(tmp_path)

    with pytest.raises(
        RuntimeError,
        match="DISCORD_TOKEN is not set",
    ):
        runpy.run_path(
            module_path,
            run_name="__main__",
        )
