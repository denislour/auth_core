from fastapi import Depends, Request, HTTPException
from .services.auth import AuthService
from .schemas.user import UserInDb

def get_auth_service() -> AuthService:
    return AuthService.get_instance()

async def get_current_user(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
) -> UserInDb:
    try:
        token = auth_service.extract_token(request.headers.get("Authorization"))
        user = await auth_service.verify_token(token)
        request.state.user = user
        return user
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e)) 
