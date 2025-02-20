class AuthException(Exception):
    """Base exception for auth errors"""
    pass

class InvalidCredentialsException(AuthException):
    """Raised when credentials are invalid"""
    pass

class UnauthorizedException(AuthException):
    """Raised when user is not authorized"""
    pass

class PermissionDeniedException(AuthException):
    """Raised when user doesn't have required permissions"""
    pass

class UserNotFoundException(AuthException):
    """Raised when user is not found"""
    pass

class RoleNotFoundException(AuthException):
    """Raised when role is not found"""
    pass

class PermissionNotFoundException(AuthException):
    """Raised when permission is not found"""
    pass 
