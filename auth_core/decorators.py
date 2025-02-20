from functools import wraps
from typing import List, Optional, Callable, Any
from fastapi import HTTPException, Request
from .services.auth import AuthService
from starlette.middleware.base import BaseHTTPMiddleware

class PermissionContext:
    """
    Context class for storing permission-related services and functions.
    This context is created per request to ensure request-level isolation.
    """
    def __init__(self):
        self.auth_service: Optional[AuthService] = None
        self.get_current_user: Optional[Callable] = None

class PermissionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for handling permission context initialization.
    
    This middleware should be added to the FastAPI application after configuring
    the auth_service and get_current_user function.
    
    Example:
        ```python
        from fastapi import FastAPI
        from auth_core import PermissionMiddleware
        
        app = FastAPI()
        
        # Configure the middleware
        permission_middleware = PermissionMiddleware()
        permission_middleware.auth_service = your_auth_service
        permission_middleware.get_current_user = your_get_current_user_func
        
        # Add middleware to app
        app.add_middleware(permission_middleware)
        ```
    """
    def __init__(self):
        super().__init__(None)
        self.auth_service: Optional[AuthService] = None
        self.get_current_user: Optional[Callable] = None
    
    def configure(
        self, 
        auth_service: AuthService, 
        get_current_user: Callable
    ) -> None:
        """
        Configure the middleware with required services.
        
        Args:
            auth_service: An instance of AuthService for permission verification
            get_current_user: A callable that returns the current user
        """
        self.auth_service = auth_service
        self.get_current_user = get_current_user

    async def dispatch(self, request: Request, call_next):
        """
        Dispatch method that runs on each request.
        Creates a new permission context and attaches it to the request state.

        Args:
            request: The incoming request
            call_next: The next middleware/route handler
        """
        if not self.auth_service or not self.get_current_user:
            raise RuntimeError(
                "PermissionMiddleware not configured. "
                "Call configure() with auth_service and get_current_user first."
            )

        context = PermissionContext()
        context.auth_service = self.auth_service
        context.get_current_user = self.get_current_user
        request.state.permission_context = context

        return await call_next(request)

def requires_permissions(permissions: List[str]):
    """
    Decorator for protecting routes with permission requirements.
    
    This decorator requires the PermissionMiddleware to be properly configured
    and added to the FastAPI application.
    
    Args:
        permissions: List of permission strings required to access the route
        
    Example:
        ```python
        from fastapi import FastAPI, Request
        from auth_core import requires_permissions
        
        app = FastAPI()
        
        @app.get("/protected")
        @requires_permissions(["users:read"])
        async def protected_route(request: Request):
            return {"message": "Access granted"}
        ```
        
    Raises:
        HTTPException: If permission check fails or middleware is not configured
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(request: Request, *args: Any, **kwargs: Any):
            try:
                if not hasattr(request.state, 'permission_context'):
                    raise RuntimeError(
                        "PermissionMiddleware not found. "
                        "Make sure to add PermissionMiddleware to your FastAPI app."
                    )

                context = request.state.permission_context
                current_user = await context.get_current_user()

                await context.auth_service.verify_permissions(
                    current_user, 
                    permissions
                )

                return await func(request, *args, **kwargs)
                
            except Exception as e:
                raise HTTPException(
                    status_code=403,
                    detail=str(e)
                )
        return wrapper
    return decorator
