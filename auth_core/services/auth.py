from datetime import timedelta
from typing import List
from uuid import UUID

from ..interfaces.user import UserRepository
from ..interfaces.role import RoleRepository
from ..interfaces.permission import PermissionRepository
from ..security.password import verify_password
from ..security.jwt import JWTHandler
from ..schemas.user import UserInDb
from ..exceptions import (
    InvalidCredentialsException,
    UnauthorizedException,
    PermissionDeniedException,
    UserNotFoundException
)

class AuthService:
    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        jwt_handler: JWTHandler,
        token_expire_minutes: int = 30
    ):
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.jwt_handler = jwt_handler
        self.token_expire_minutes = token_expire_minutes

    async def authenticate_user(self, email: str, password: str) -> UserInDb:
        try:
            user = await self.user_repository.get_by_email(email)
        except UserNotFoundException:
            raise InvalidCredentialsException()

        if not verify_password(password, user.hashed_password):
            raise InvalidCredentialsException()

        if not user.is_active:
            raise UnauthorizedException("User account is disabled")

        return user

    async def get_user_permissions(self, user: UserInDb) -> List[str]:
        try:
            roles = await self.role_repository.get_by_ids(user.role_ids)
            
            permissions = set()
            for role in roles:
                role_permissions = await self.permission_repository.get_by_ids(
                    role.permission_ids
                )
                permissions.update([
                    f"{p.resource}:{p.action}" 
                    for p in role_permissions
                ])
                
            return list(permissions)
        except Exception as e:
            raise UnauthorizedException("Failed to get user permissions") from e

    async def create_access_token(self, user: UserInDb) -> str:
        try:
            permissions = await self.get_user_permissions(user)
            expires_delta = timedelta(minutes=self.token_expire_minutes)
            
            return self.jwt_handler.create_token(
                subject=str(user.id),
                permissions=permissions,
                expires_delta=expires_delta
            )
        except Exception as e:
            raise UnauthorizedException("Failed to create access token") from e

    async def verify_permissions(
        self,
        user: UserInDb,
        required_permissions: List[str]
    ) -> bool:
        user_permissions = await self.get_user_permissions(user)
        
        if not all(perm in user_permissions for perm in required_permissions):
            raise PermissionDeniedException(
                f"User lacks required permissions: {required_permissions}"
            )
        
        return True

    async def verify_token(self, token: str) -> UserInDb:
        try:
            payload = self.jwt_handler.verify_token(token)
            user = await self.user_repository.get_by_uuid(UUID(payload.sub))
            
            if not user:
                raise UnauthorizedException("User not found")
                
            if not user.is_active:
                raise UnauthorizedException("User is inactive")
                
            return user
        except Exception as e:
            raise UnauthorizedException("Invalid token") from e
