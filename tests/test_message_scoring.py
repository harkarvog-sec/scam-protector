from types import SimpleNamespace

from scam_protector import (
    message_score,
    SUSPICIOUS_MESSAGE_WORDS,
)


def make_message(
    content="Hello everyone",
    mentions=None,
    mention_everyone=False,
):
    """
    Create a simple fake Discord message for testing
    message_score() without connecting to Discord.
    """

    if mentions is None:
        mentions = []

    return SimpleNamespace(
        content=content,
        mentions=mentions,
        mention_everyone=mention_everyone,
    )


def test_normal_message_gets_zero_points():
    message = make_message(
        content="Hello, how is everyone doing today?"
    )

    score, reasons = message_score(message)

    assert score == 0
    assert reasons == []


def test_suspicious_phrase_adds_30_points():
    # Use an actual suspicious phrase configured by the application.
    phrase = SUSPICIOUS_MESSAGE_WORDS[0]

    message = make_message(
        content=f"This message contains {phrase}"
    )

    score, reasons = message_score(message)

    assert score == 30
    assert "Suspicious phrase detected: +30" in reasons


def test_url_adds_20_points():
    message = make_message(
        content="Visit https://example.com for more information"
    )

    score, reasons = message_score(message)

    assert score == 20
    assert "Message contains URL: +20" in reasons


def test_four_mentions_do_not_trigger_excessive_mentions():
    message = make_message(
        content="Hello",
        mentions=[
            object(),
            object(),
            object(),
            object(),
        ]
    )

    score, reasons = message_score(message)

    assert score == 0
    assert "Excessive mentions: +30" not in reasons


def test_five_mentions_adds_30_points():
    message = make_message(
        content="Hello",
        mentions=[
            object(),
            object(),
            object(),
            object(),
            object(),
        ]
    )

    score, reasons = message_score(message)

    assert score == 30
    assert "Excessive mentions: +30" in reasons


def test_everyone_abuse_adds_40_points():
    message = make_message(
        content="@everyone important announcement",
        mention_everyone=True,
    )

    score, reasons = message_score(message)

    assert score == 40
    assert "@everyone/@here abuse: +40" in reasons


def test_suspicious_phrase_and_url_scores_are_combined():
    phrase = SUSPICIOUS_MESSAGE_WORDS[0]

    message = make_message(
        content=f"{phrase} https://example.com"
    )

    score, reasons = message_score(message)

    assert score == 50

    assert "Suspicious phrase detected: +30" in reasons
    assert "Message contains URL: +20" in reasons


def test_multiple_risk_signals_accumulate():
    phrase = SUSPICIOUS_MESSAGE_WORDS[0]

    message = make_message(
        content=f"{phrase} https://example.com @everyone",
        mentions=[
            object(),
            object(),
            object(),
            object(),
            object(),
        ],
        mention_everyone=True,
    )

    score, reasons = message_score(message)

    # Suspicious phrase = 30
    # URL = 20
    # 5 mentions = 30
    # @everyone = 40
    #
    # Total = 120
    assert score == 120

    assert "Suspicious phrase detected: +30" in reasons
    assert "Message contains URL: +20" in reasons
    assert "Excessive mentions: +30" in reasons
    assert "@everyone/@here abuse: +40" in reasons
