import pytest
from pydantic import ValidationError

from app.config import Settings


@pytest.mark.parametrize("password", ["", "short", "CHANGE_ME_GENERATE_LOCALLY"])
def test_rejects_placeholder_password(password):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, postgres_password=password)


def test_password_special_characters_are_preserved_and_repr_is_redacted():
    value = "fixture-password@:/#%with-specials"
    settings = Settings(_env_file=None, postgres_password=value)
    assert settings.database_url.password == value
    assert value not in repr(settings)
    assert value not in str(settings.database_url)


@pytest.mark.parametrize("origin", ["*", "http://localhost:5173/path", "not-a-url"])
def test_rejects_invalid_cors_origins(origin):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, cors_origins=[origin])
