from uuid import UUID
from pydantic import BaseModel


class PermissionBase(BaseModel):
    name: str
    description: str | None = None
    resource: str
    action: str


class PermissionCreate(BaseModel):
    ...


class PermissionInDb(BaseModel):
    id: UUID
