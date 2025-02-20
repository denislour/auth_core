from typing import Protocol, Optional
from uuid import UUID
from ..schemas.user import UserCreate, UserInDb

class UserRepository(Protocol):
    async def get_by_email(self, email: str) -> Optional[UserInDb]:
        ...

    async def get_by_uuid(self, user_id: UUID) -> Optional[UserInDb]:
        ...

    async def create(self, user: UserCreate) -> UserInDb:
        ...

    async def update(self, user_id: UUID, user_data: dict) -> UserInDb:
        ...

    async def delete(self, user_id: UUID) -> bool:
        ...
