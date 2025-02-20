from uuid import UUID
from pydantic import BaseModel


class RoleBase(BaseModel):
    name: str
    description: str | None = None


class RoleCreate(RoleBase):
    permission_ids: list[UUID]

class RoleInDb(BaseModel):
    id: UUID
    permission_ids: list[UUID]
