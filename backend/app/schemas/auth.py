from pydantic import Field, SecretStr, field_validator

from app.core.enums import UserRole
from app.schemas.common import Schema
from app.schemas.user import UserCreate, UserResponse


class UserRegister(UserCreate):
    pass


class UserLogin(Schema):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=4096, exclude=True)

    @field_validator("username")
    @classmethod
    def normalize_login(cls, value: str) -> str:
        return value.strip().lower()


class TokenResponse(Schema):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(Schema):
    """Optional empty JSON body; the refresh credential is an HTTP-only cookie."""


class RoleUpdate(Schema):
    role: UserRole


class UserStatusUpdate(Schema):
    is_active: bool = Field(strict=True)


class UserPage(Schema):
    items: list[UserResponse]
    total: int
    limit: int
    offset: int
