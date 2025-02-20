from datetime import datetime
from pydantic import BaseModel


class JWTPayload(BaseModel):
    sub: str
    exp: datetime
    permissions: list[str] | None = None

    iss: str | None = None
    aud: list[str] | None = None
