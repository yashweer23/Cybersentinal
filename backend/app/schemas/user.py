from pydantic import AwareDatetime, Field, SecretStr, field_validator

from app.core.enums import UserRole
from app.core.validation import normalize_email, normalize_username, validate_password
from app.schemas.common import Schema, UpdatedResponse


class UserIdentity(Schema):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(max_length=254)
    full_name: str | None = Field(default=None, max_length=150)

    _username = field_validator("username")(normalize_username)
    _email = field_validator("email")(normalize_email)


class UserCreate(UserIdentity):
    # Role assignment is deliberately not accepted from a registration payload.
    password: SecretStr = Field(exclude=True)

    @field_validator("password")
    @classmethod
    def check_password(cls, value: SecretStr) -> SecretStr:
        validate_password(value.get_secret_value())
        return value


class UserResponse(UserIdentity, UpdatedResponse):
    role: UserRole
    is_active: bool
    last_login: AwareDatetime | None
