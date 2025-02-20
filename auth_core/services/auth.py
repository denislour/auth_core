from datetime import timedelta
from typing import List
from uuid import UUID
from fastapi import HTTPException

from ..interfaces.user import UserRepository
from ..interfaces.role import RoleRepository
from ..interfaces.permission import PermissionRepository
from ..security.jwt import JWTHandler
from ..schemas.user import UserInDb
from ..exceptions import (
    UnauthorizedException,
    PermissionDeniedException,
)

class AuthService:
    _instance = None
    BEARER_PREFIX = "Bearer "

    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        jwt_handler: JWTHandler,
        token_expire_minutes: int = 30
    ):
        if AuthService._instance is not None:
            raise Exception("AuthService is a singleton!")

        self.user_repository = user_repository
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.jwt_handler = jwt_handler
        self.token_expire_minutes = token_expire_minutes
        AuthService._instance = self

    @staticmethod
    def get_instance() -> 'AuthService':
        if AuthService._instance is None:
            raise Exception("AuthService must be initialized first!")
        return AuthService._instance

    def extract_token(self, authorization: str | None) -> str:
        """Extract JWT token from Authorization header"""
        if not authorization:
            raise HTTPException(status_code=401, detail="Authorization header is missing")

        if not authorization.startswith(self.BEARER_PREFIX):
            raise HTTPException(
                status_code=401, 
                detail="Invalid authorization header format. Use 'Bearer <token>'"
            )

        return authorization[len(self.BEARER_PREFIX):]

    async def verify_token(self, token: str) -> UserInDb:
        """Verify JWT token and return active user"""
        try:
            user = await self.user_repository.get_by_uuid(
                UUID(self.jwt_handler.verify_token(token).sub)
            )
            if not user or not user.is_active:
                raise UnauthorizedException("User not found or inactive")
            return user
        except Exception as e:
            raise UnauthorizedException("Invalid token") from e

    async def verify_permissions(self, user: UserInDb, required_permissions: List[str]) -> bool:
        """Verify if user has all required permissions"""
        try:
            roles = await self.role_repository.get_by_ids(user.role_ids)
            permissions = {f"{p.resource}:{p.action}" 
                         for role in roles 
                         for p in await self.permission_repository.get_by_ids(role.permission_ids)}

            if not all(perm in permissions for perm in required_permissions):
                raise PermissionDeniedException(f"User lacks required permissions: {required_permissions}")
            return True

        except Exception as e:
            raise PermissionDeniedException(str(e))
