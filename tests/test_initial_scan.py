import datetime
from types import SimpleNamespace

from scam_protector import initial_scan


def make_member(
    age_days,
    name="normaluser",
    display_name="normaluser",
    avatar=object(),
):
    created_at = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=age_days)
    )

    return SimpleNamespace(
        created_at=created_at,
        name=name,
        display_name=display_name,
        avatar=avatar,
    )


def test_initial_scan_returns_zero_for_safe_account():
    member = make_member(
        age_days=100,
        name="victor",
        display_name="victor",
        avatar=object(),
    )

    score, reasons = initial_scan(
        member,
        minimum_age=7,
    )

    assert score == 0
    assert reasons == []


def test_initial_scan_adds_account_age_risk():
    member = make_member(
        age_days=2,
        name="victor",
        display_name="victor",
        avatar=object(),
    )

    score, reasons = initial_scan(
        member,
        minimum_age=7,
    )

    assert score == 30
    assert "Account age risk: +30" in reasons


def test_initial_scan_adds_username_risk():
    member = make_member(
        age_days=100,
        name="free_nitro_claim",
        display_name="free_nitro_claim",
        avatar=object(),
    )

    score, reasons = initial_scan(
        member,
        minimum_age=7,
    )

    assert score == 20
    assert "Username risk: +20" in reasons


def test_initial_scan_adds_profile_risk():
    member = make_member(
        age_days=100,
        name="victor",
        display_name="victor",
        avatar=None,
    )

    score, reasons = initial_scan(
        member,
        minimum_age=7,
    )

    assert score == 5
    assert "Profile risk: +5" in reasons


def test_initial_scan_combines_multiple_signals():
    member = make_member(
        age_days=0,
        name="free_nitro_claim",
        display_name="free_nitro_claim",
        avatar=None,
    )

    score, reasons = initial_scan(
        member,
        minimum_age=7,
    )

    # Account age = 40
    # Suspicious username = 20
    # Missing avatar = 5
    #
    # Total = 65
    assert score == 65

    assert "Account age risk: +40" in reasons
    assert "Username risk: +20" in reasons
    assert "Profile risk: +5" in reasons


def test_initial_scan_preserves_reason_order():
    member = make_member(
        age_days=0,
        name="free_nitro_claim",
        display_name="free_nitro_claim",
        avatar=None,
    )

    score, reasons = initial_scan(
        member,
        minimum_age=7,
    )

    assert score == 65

    assert reasons == [
        "Account age risk: +40",
        "Username risk: +20",
        "Profile risk: +5",
    ]
