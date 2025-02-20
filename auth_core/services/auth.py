from typing import List
from uuid import UUID
from fastapi import HTTPException

from ..interfaces.user import UserRepository
from ..interfaces.role import RoleRepository
from ..interfaces.permission import PermissionRepository
from ..schemas.user import UserInDb
from ..exceptions import (
    UnauthorizedException,
    PermissionDeniedException,
)
from .token import TokenService
from ..schemas.token import TokenPair
from ..security.password import verify_password

class AuthService:
    _instance = None
    BEARER_PREFIX = "Bearer "

    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        permission_repository: PermissionRepository,
        token_service: TokenService
    ):
        if AuthService._instance is not None:
            raise Exception("AuthService is a singleton!")

        self._user_repository = user_repository
        self._role_repository = role_repository
        self._permission_repository = permission_repository
        self._token_service = token_service
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
        """Verify token and return user"""
        token_data = await self._token_service.verify_token(token)

        if token_data.token_type != "access":
            raise UnauthorizedException("Invalid token type")
            
        user = await self._user_repository.get_by_uuid(token_data.user_id)
        if not user or not user.is_active:
            raise UnauthorizedException("User not found or inactive")
            
        return user

    async def verify_permissions(self, user: UserInDb, required_permissions: List[str]) -> bool:
        """Verify if user has all required permissions"""
        try:
            permissions = await self._get_user_permissions(user.id)
            if not all(perm in permissions for perm in required_permissions):
                raise PermissionDeniedException(
                    f"User lacks required permissions: {required_permissions}"
                )
            return True
        except Exception as e:
            raise PermissionDeniedException(str(e))

    async def authenticate_user(self, email: str, password: str) -> UserInDb:
        """Authenticate user with email and password"""
        user = await self._user_repository.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password) or not user.is_active:
            raise UnauthorizedException("Invalid credentials or inactive user")
        return user

    async def logout(self, token: str) -> None:
        """Logout user by revoking their token"""
        await self._token_service.revoke_token(token)

    async def login(self, email: str, password: str) -> TokenPair:
        """Login user and return token pair"""
        user = await self.authenticate_user(email, password)
        permissions = await self._get_user_permissions(user.id)
        return await self._token_service.create_token_pair(user.id, permissions)

    async def refresh_token(self, refresh_token: str) -> str:
        """Refresh access token"""
        token_data = await self._token_service.verify_token(refresh_token)
        permissions = await self._get_user_permissions(token_data.user_id)
        return await self._token_service.refresh_access_token(refresh_token, permissions)

    async def _get_user_permissions(self, user_id: UUID) -> list[str]:
        """Get all permissions for user"""
        user = await self._user_repository.get_by_uuid(user_id)
        roles = await self._role_repository.get_by_ids(user.role_ids)
        return [
            f"{p.resource}:{p.action}"
            for role in roles
            for p in await self._permission_repository.get_by_ids(role.permission_ids)
        ]
