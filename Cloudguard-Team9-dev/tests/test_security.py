from cloudguard.core.security import (
    hash_password,
    verify_password,
)


def test_password_is_hashed() -> None:
    password = "CloudGuard-Test-Password"

    password_hash = hash_password(password)

    assert password_hash != password


def test_correct_password_verifies() -> None:
    password = "CloudGuard-Test-Password"

    password_hash = hash_password(password)

    assert verify_password(
        password,
        password_hash,
    ) is True


def test_wrong_password_fails() -> None:
    password_hash = hash_password(
        "CloudGuard-Correct-Password"
    )

    assert verify_password(
        "wrong-password",
        password_hash,
    ) is False

from cloudguard.core.security import (
    create_access_token,
    decode_access_token,
)


def test_access_token_contains_user_identity() -> None:
    token = create_access_token(
        username="cloud-engineer",
        role="cloud_engineer",
    )

    payload = decode_access_token(token)

    assert payload["sub"] == "cloud-engineer"
    assert payload["role"] == "cloud_engineer"
    assert "exp" in payload


def test_invalid_access_token_fails() -> None:
    try:
        decode_access_token("invalid-token")
        assert False
    except ValueError as error:
        assert str(error) == "Invalid or expired access token"