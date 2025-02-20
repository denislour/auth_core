from typing import Protocol, Optional, List
from uuid import UUID
from ..schemas.role import RoleCreate, RoleInDb

class RoleRepository(Protocol):
    async def get_by_id(self, role_id: UUID) -> Optional[RoleInDb]:
        ...

    async def get_by_name(self, name: str) -> Optional[RoleInDb]:
        ...

    async def get_by_ids(self, role_ids: List[UUID]) -> List[RoleInDb]:
        ...

    async def create(self, role: RoleCreate) -> RoleInDb:
        ...

    async def update(self, role_id: UUID, role_data: dict) -> RoleInDb:
        ...

    async def delete(self, role_id: UUID) -> bool:
        ...
