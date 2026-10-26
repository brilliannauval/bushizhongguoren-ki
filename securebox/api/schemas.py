from __future__ import annotations

import re
from datetime import date
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    username: str = Field(min_length=3, max_length=32)
    password: Annotated[str, StringConstraints(min_length=12, max_length=128, strip_whitespace=False)]
    invitation_code: str | None = Field(default=None, max_length=128)


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=128)
    password: Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)]


class ProfileInput(StrictModel):
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    contact_email: str | None = Field(default=None, max_length=254)
    phone: str | None = Field(default=None, max_length=40)
    address: str | None = Field(default=None, max_length=200)
    date_of_birth: str | None = Field(default=None, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")
    national_id: str | None = Field(default=None, max_length=64)

    @field_validator("date_of_birth")
    @classmethod
    def validate_date_of_birth(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise ValueError("Invalid calendar date") from exc
        return value

    @field_validator("contact_email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[^\s@]{1,64}@[^\s@.]{1,190}(?:\.[^\s@.]{1,63})+", value):
            raise ValueError("Invalid email address")
        return value
