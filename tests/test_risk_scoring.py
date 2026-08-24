import datetime
from types import SimpleNamespace

from scam_protector import (
    account_age_score,
    username_score,
    profile_score,
)


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


def test_brand_new_account_gets_high_age_risk():
    member = make_member(age_days=0)

    score = account_age_score(
        member,
        minimum_age=7
    )

    assert score == 40


def test_two_day_old_account_gets_age_risk():
    member = make_member(age_days=2)

    score = account_age_score(
        member,
        minimum_age=7
    )

    assert score == 30


def test_account_below_minimum_age_gets_risk():
    member = make_member(age_days=5)

    score = account_age_score(
        member,
        minimum_age=7
    )

    assert score == 20


def test_old_account_has_no_age_risk():
    member = make_member(age_days=100)

    score = account_age_score(
        member,
        minimum_age=7
    )

    assert score == 0


def test_suspicious_username_gets_risk_points():
    member = make_member(
        age_days=100,
        name="free_nitro_claim",
        display_name="free_nitro_claim"
    )

    score = username_score(member)

    assert score == 20


def test_normal_username_has_no_username_risk():
    member = make_member(
        age_days=100,
        name="victor",
        display_name="victor"
    )

    score = username_score(member)

    assert score == 0


def test_missing_avatar_adds_profile_risk():
    member = make_member(
        age_days=100,
        avatar=None
    )

    score = profile_score(member)

    assert score == 5


def test_existing_avatar_has_no_profile_risk():
    member = make_member(
        age_days=100,
        avatar=object()
    )

    score = profile_score(member)

    assert score == 0
