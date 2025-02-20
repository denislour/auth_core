from uuid import UUID
from pydantic import BaseModel
from typing import Optional

class TokenData(BaseModel):
    """Schema for decoded token data"""
    user_id: UUID
    token_type: str
    permissions: list[str] = []
    exp: Optional[int] = None

class TokenPair(BaseModel):
    """Schema for token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
