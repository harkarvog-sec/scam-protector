import sqlite3

import scam_protector


def use_temp_database(tmp_path, monkeypatch):
    db_file = tmp_path / "test_scam_protector.db"

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

    return db_file


def test_save_and_get_server_config(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    scam_protector.save_server_config(
        guild_id=123,
        log_channel_id=20,
        alert_channel_id=30,
        general_channel_id=10,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    config = scam_protector.get_server_config(123)

    assert config is not None
    assert config["guild_id"] == 123
    assert config["general_channel_id"] == 10
    assert config["log_channel_id"] == 20
    assert config["alert_channel_id"] == 30
    assert config["min_account_age"] == 7
    assert config["monitor_threshold"] == 30
    assert config["alert_threshold"] == 60
    assert config["ban_threshold"] == 80


def test_unknown_server_returns_none(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    config = scam_protector.get_server_config(999)

    assert config is None


def test_new_user_score_defaults_to_zero(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    score = scam_protector.get_user_score(
        guild_id=123,
        user_id=456,
    )

    assert score == 0


def test_add_user_score_creates_score(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    score = scam_protector.add_user_score(
        guild_id=123,
        user_id=456,
        amount=40,
    )

    assert score == 40


def test_add_user_score_accumulates(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    scam_protector.add_user_score(
        guild_id=123,
        user_id=456,
        amount=40,
    )

    score = scam_protector.add_user_score(
        guild_id=123,
        user_id=456,
        amount=30,
    )

    assert score == 70

    stored_score = scam_protector.get_user_score(
        guild_id=123,
        user_id=456,
    )

    assert stored_score == 70


def test_save_server_config_creates_statistics_row(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    scam_protector.save_server_config(
        guild_id=123,
        log_channel_id=20,
        alert_channel_id=30,
        general_channel_id=10,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    conn = scam_protector.get_db()

    row = conn.execute(
        """
        SELECT banned, alerts
        FROM statistics
        WHERE guild_id = ?
        """,
        (123,),
    ).fetchone()

    conn.close()

    assert row is not None
    assert row["banned"] == 0
    assert row["alerts"] == 0


def test_increment_banned_updates_statistics(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    scam_protector.save_server_config(
        guild_id=123,
        log_channel_id=20,
        alert_channel_id=30,
        general_channel_id=10,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    scam_protector.increment_banned(123)

    conn = scam_protector.get_db()

    row = conn.execute(
        """
        SELECT banned
        FROM statistics
        WHERE guild_id = ?
        """,
        (123,),
    ).fetchone()

    conn.close()

    assert row["banned"] == 1


def test_increment_alerts_updates_statistics(
    tmp_path,
    monkeypatch,
):
    use_temp_database(
        tmp_path,
        monkeypatch,
    )

    scam_protector.save_server_config(
        guild_id=123,
        log_channel_id=20,
        alert_channel_id=30,
        general_channel_id=10,
        min_account_age=7,
        monitor_threshold=30,
        alert_threshold=60,
        ban_threshold=80,
    )

    scam_protector.increment_alerts(123)

    conn = scam_protector.get_db()

    row = conn.execute(
        """
        SELECT alerts
        FROM statistics
        WHERE guild_id = ?
        """,
        (123,),
    ).fetchone()

    conn.close()

    assert row["alerts"] == 1
