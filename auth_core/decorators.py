from functools import wraps
from typing import List, Callable, Any
from fastapi import Request, HTTPException, Depends
from .dependencies import get_current_user, get_auth_service
from .services.auth import AuthService

def requires_permissions(permissions: List[str]):
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(
            request: Request,
            user = Depends(get_current_user),
            auth_service: AuthService = Depends(get_auth_service),
            *args: Any,
            **kwargs: Any
        ):
            try:
                await auth_service.verify_permissions(user, permissions)
                return await func(request, *args, **kwargs)
            except Exception as e:
                raise HTTPException(status_code=403, detail=str(e))
        return wrapper
    return decorator
