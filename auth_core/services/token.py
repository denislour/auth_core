from fastapi import HTTPException

class TokenService:
    _instance = None
    BEARER_PREFIX = "Bearer "

    def __init__(self):
        if TokenService._instance is not None:
            raise Exception("TokenService is a singleton!")
        TokenService._instance = self

    @staticmethod
    def get_instance() -> 'TokenService':
        if TokenService._instance is None:
            TokenService._instance = TokenService()
        return TokenService._instance

    def extract_token(self, authorization: str | None) -> str:
        if not authorization:
            raise HTTPException(
                status_code=401,
                detail="Authorization header is missing"
            )

        if not authorization.startswith(self.BEARER_PREFIX):
            raise HTTPException(
                status_code=401,
                detail="Invalid authorization header format. Use 'Bearer <token>'"
            )

        return authorization[len(self.BEARER_PREFIX):] 
