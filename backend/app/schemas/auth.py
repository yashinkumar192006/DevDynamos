"""Request/response schemas for authentication and authorization endpoints."""

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    """Credentials for ``POST /api/v1/auth/login``.

    Extra fields are ignored — a client cannot smuggle authorization data
    (``role``, ``is_admin``, …) into the login call.
    """

    model_config = ConfigDict(extra="ignore")

    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class PermissionInfo(BaseModel):
    resource: str
    action: str


class RoleInfo(BaseModel):
    name: str
    description: str | None = None


class UserProfile(BaseModel):
    """The authenticated user's profile — resolved from the database."""

    id: str
    username: str
    email: str
    full_name: str
    department: str | None = None
    employee_id: str | None = None
    is_active: bool
    roles: list[RoleInfo]
    permissions: list[PermissionInfo]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserProfile


class WhoAmIResponse(BaseModel):
    """Verified identity behind the current credential (user or service)."""

    kind: str  # "user" | "service"
    id: str
    display_name: str
    username: str | None = None
    roles: list[str] = []
    scopes: list[str] = []


class AdminUserView(BaseModel):
    """Row in the admin user listing."""

    id: str
    username: str
    email: str
    full_name: str
    department: str | None = None
    is_active: bool
    roles: list[str]


class MessageResponse(BaseModel):
    message: str
