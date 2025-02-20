from uuid import UUID
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserInDb(UserBase):
    id: UUID
    hash_password: str
    is_active: bool = True
    roles: list[str] = ["user"]
