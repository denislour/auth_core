from datetime import timedelta
from uuid import UUID

from ..interfaces.token import TokenRepository
from ..schemas.token import TokenPair, TokenData
from ..security.jwt import JWTHandler
from ..exceptions import UnauthorizedException

class TokenService:
    def __init__(
        self,
        token_repository: TokenRepository,
        jwt_handler: JWTHandler,
        access_token_expires: int = 30,
        refresh_token_expires: int = 7 * 24 * 60
    ):
        self._token_repository = token_repository
        self._jwt_handler = jwt_handler
        self._access_token_expires = timedelta(minutes=access_token_expires)
        self._refresh_token_expires = timedelta(minutes=refresh_token_expires)

    async def create_token_pair(self, user_id: UUID, permissions: list[str]) -> TokenPair:
        """Create access and refresh token pair"""
        access_token = self._create_access_token(user_id, permissions)
        refresh_token = self._create_refresh_token(user_id)

        await self._token_repository.add_to_cache(
            access_token,
            str(user_id),
            self._access_token_expires
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=int(self._access_token_expires.total_seconds())
        )

    def _create_access_token(self, user_id: UUID, permissions: list[str]) -> str:
        return self._jwt_handler.create_token(
            subject=str(user_id),
            permissions=permissions,
            token_type="access",
            expires_delta=self._access_token_expires
        )

    def _create_refresh_token(self, user_id: UUID) -> str:
        return self._jwt_handler.create_token(
            subject=str(user_id),
            token_type="refresh",
            expires_delta=self._refresh_token_expires
        )

    async def verify_token(self, token: str) -> TokenData:
        """Verify and decode token"""
        if await self._token_repository.is_blacklisted(token):
            raise UnauthorizedException("Token has been revoked")

        try:
            if cached_user_id := await self._token_repository.get_cached_user_id(token):
                return TokenData(
                    user_id=UUID(cached_user_id),
                    token_type="access"
                )

            payload = self._jwt_handler.decode_token(token)
            token_data = TokenData(
                user_id=UUID(payload["sub"]),
                token_type=payload.get("token_type", "access"),
                permissions=payload.get("permissions", []),
                exp=payload.get("exp")
            )

            if token_data.token_type == "access":
                await self._token_repository.add_to_cache(
                    token,
                    str(token_data.user_id),
                    self._access_token_expires
                )

            return token_data

        except Exception as e:
            raise UnauthorizedException("Invalid token") from e

    async def refresh_access_token(self, refresh_token: str, permissions: list[str]) -> str:
        """Create new access token from refresh token"""
        try:
            payload = self._jwt_handler.decode_token(refresh_token)
            if payload.get("token_type") != "refresh":
                raise UnauthorizedException("Invalid refresh token")
            return self._create_access_token(UUID(payload["sub"]), permissions)
        except Exception as e:
            raise UnauthorizedException("Invalid refresh token") from e

    async def revoke_token(self, token: str) -> None:
        """Revoke token by adding to blacklist"""
        await self._token_repository.add_to_blacklist(token, self._access_token_expires)
        await self._token_repository.remove_from_cache(token) 
