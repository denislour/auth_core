from datetime import datetime, timedelta
from jose import jwt
from ..schemas.jwt import JWTPayload

class JWTHandler:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_token(
        self, 
        subject: str,
        permissions: list[str] | None = None,
        expires_delta: timedelta | None = None
    ) -> str:
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))

        payload = JWTPayload(
            sub=subject,
            exp=expire,
            permissions=permissions
        )

        return jwt.encode(
            payload.model_dump(exclude_none=True),
            self.secret_key,
            algorithm=self.algorithm
        )

    def decode_token(self, token: str) -> dict:
        return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
