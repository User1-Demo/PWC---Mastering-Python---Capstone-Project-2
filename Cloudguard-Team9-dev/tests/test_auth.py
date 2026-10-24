from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from cloudguard.core.auth import get_current_user, require_role
from cloudguard.models.user import User


def test_allowed_role_is_accepted() -> None:
    user = User(
        id=1,
        username="security-officer",
        password_hash="test",
        role="security_officer",
        is_active=True,
    )

    dependency = require_role("security_officer")

    # FastAPI dependencies are represented by defaults, so get
    # the underlying checker and call it directly.
    result = dependency(current_user=user)

    assert result == user


def test_disallowed_role_is_rejected() -> None:
    user = User(
        id=2,
        username="cloud-engineer",
        password_hash="test",
        role="cloud_engineer",
        is_active=True,
    )

    dependency = require_role("security_officer")

    with pytest.raises(HTTPException) as error:
        dependency(current_user=user)

    assert error.value.status_code == 403
    assert error.value.detail == "Insufficient permissions"


def test_admin_can_match_admin_role() -> None:
    user = User(
        id=3,
        username="admin",
        password_hash="test",
        role="admin",
        is_active=True,
    )

    dependency = require_role(
        "admin",
        "cloud_engineer",
    )

    assert dependency(current_user=user) == user

def test_get_current_user_returns_active_user() -> None:
    db = MagicMock()

    user = User(
        id=1,
        username="cloud-engineer",
        password_hash="test",
        role="cloud_engineer",
        is_active=True,
    )

    credentials = MagicMock()
    credentials.credentials = "valid-token"

    db.scalar.return_value = user

    with patch(
        "cloudguard.core.auth.decode_access_token",
        return_value={
            "sub": "cloud-engineer",
            "role": "cloud_engineer",
        },
    ):
        result = get_current_user(
            credentials=credentials,
            db=db,
        )

    assert result == user

def test_get_current_user_rejects_invalid_token() -> None:
    db = MagicMock()

    credentials = MagicMock()
    credentials.credentials = "invalid-token"

    with patch(
        "cloudguard.core.auth.decode_access_token",
        side_effect=ValueError(
            "Invalid or expired access token"
        ),
    ), pytest.raises(HTTPException) as error:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert error.value.status_code == 401
    assert error.value.detail == (
        "Invalid or expired access token"
    )

def test_get_current_user_rejects_token_without_username() -> None:
    db = MagicMock()

    credentials = MagicMock()
    credentials.credentials = "token-without-subject"

    with patch(
        "cloudguard.core.auth.decode_access_token",
        return_value={
            "role": "cloud_engineer",
        },
    ), pytest.raises(HTTPException) as error:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid access token"

def test_get_current_user_rejects_inactive_user() -> None:
    db = MagicMock()

    inactive_user = User(
        id=2,
        username="disabled-user",
        password_hash="test",
        role="cloud_engineer",
        is_active=False,
    )

    credentials = MagicMock()
    credentials.credentials = "valid-token"

    db.scalar.return_value = inactive_user

    with patch(
        "cloudguard.core.auth.decode_access_token",
        return_value={
            "sub": "disabled-user",
            "role": "cloud_engineer",
        },
    ), pytest.raises(HTTPException) as error:
        get_current_user(
            credentials=credentials,
            db=db,
        )

    assert error.value.status_code == 401
    assert error.value.detail == "User not found or inactive"