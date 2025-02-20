from typing import Protocol, Optional, List
from uuid import UUID
from ..schemas.permission import PermissionCreate, PermissionInDb

class PermissionRepository(Protocol):
    async def get_by_id(self, permission_id: UUID) -> Optional[PermissionInDb]:
        ...

    async def get_by_name(self, name: str) -> Optional[PermissionInDb]:
        ...

    async def get_by_ids(self, permission_ids: List[UUID]) -> List[PermissionInDb]:
        ...

    async def create(self, permission: PermissionCreate) -> PermissionInDb:
        ...

    async def update(self, permission_id: UUID, permission_data: dict) -> PermissionInDb:
        ...

    async def delete(self, permission_id: UUID) -> bool:
        ... 
