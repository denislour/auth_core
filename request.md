Không, package của chúng ta vẫn nên đóng gói cả logic nghiệp vụ chung. Hãy xem cách tổ chức hợp lý:

### 1. Cấu trúc Package Đầy đủ

```python
order_package/
├── order_package/
│   ├── __init__.py
│   ├── interfaces/
│   │   ├── __init__.py
│   │   ├── repository.py     # Interface definitions
│   │   └── services.py       # Service interfaces
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   └── order.py         # Core business logic
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   └── order.py         # API routes
│   │
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── order.py         # Pydantic models
│   │
│   └── exceptions.py         # Custom exceptions
```

### 2. Core Business Logic trong Package

```python
# order_package/services/order.py
from ..interfaces.repository import OrderRepository
from ..schemas.order import OrderCreate, OrderResponse
from ..exceptions import OrderValidationError

class OrderService:
    def __init__(self, repository: OrderRepository):
        self.repository = repository

    async def create_order(self, data: OrderCreate) -> OrderResponse:
        # Validate business rules
        await self._validate_order(data)

        # Calculate order total
        total = await self._calculate_total(data)

        # Apply any discounts
        final_total = await self._apply_discounts(total)

        # Create order with processed data
        order_data = {
            **data.dict(),
            "total": final_total,
            "status": "pending"
        }

        return await self.repository.create(order_data)

    async def _validate_order(self, data: OrderCreate):
        if data.quantity <= 0:
            raise OrderValidationError("Quantity must be positive")
        # Other validation logic...

    async def _calculate_total(self, data: OrderCreate):
        # Complex pricing logic
        return data.quantity * data.unit_price

    async def _apply_discounts(self, total: float):
        # Discount logic
        return total * 0.9 if total > 100 else total
```

### 3. Routes với Business Logic

```python
# order_package/routes/order.py
from fastapi import APIRouter, Depends, HTTPException
from ..services.order import OrderService
from ..schemas.order import OrderCreate, OrderResponse
from ..exceptions import OrderValidationError

def create_order_router(
    order_service: OrderService
) -> APIRouter:
    router = APIRouter()

    @router.post("/", response_model=OrderResponse)
    async def create_order(order: OrderCreate):
        try:
            return await order_service.create_order(order)
        except OrderValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/{order_id}")
    async def get_order(order_id: int):
        return await order_service.get_order(order_id)

    return router
```

### 4. Sử dụng trong Project

```python
# project_a/repositories/order.py
from order_package.interfaces.repository import OrderRepository
from order_package.schemas.order import OrderCreate, OrderResponse

class PostgresOrderRepository(OrderRepository):
    def __init__(self, db_session):
        self.db = db_session

    async def create(self, data: dict) -> OrderResponse:
        # Postgres specific implementation
        order = Order(**data)
        self.db.add(order)
        await self.db.commit()
        return OrderResponse.from_orm(order)

# project_a/main.py
from fastapi import FastAPI
from order_package.services.order import OrderService
from order_package.routes.order import create_order_router

app = FastAPI()

# Init dependencies
db_session = get_db_session()
order_repo = PostgresOrderRepository(db_session)
order_service = OrderService(repository=order_repo)

# Create and include router
order_router = create_order_router(order_service)
app.include_router(order_router, prefix="/api/v1/orders")
```

### 5. Mở rộng Logic trong Project

```python
# project_a/services/order.py
from order_package.services.order import OrderService as BaseOrderService

class CustomOrderService(BaseOrderService):
    async def create_order(self, data: OrderCreate):
        # Thực hiện logic cơ bản từ package
        order = await super().create_order(data)

        # Thêm logic đặc thù của project
        await self._send_notification(order)
        await self._update_inventory(order)

        return order

    async def _send_notification(self, order):
        # Project specific notification logic
        pass

    async def _update_inventory(self, order):
        # Project specific inventory logic
        pass
```

### 6. Lợi ích của Approach này:

1. **Tái sử dụng Logic:**

- Core business logic được đóng gói
- Validation rules được chuẩn hóa
- Common calculations được chia sẻ

2. **Customization:**

- Có thể extend base service
- Override specific methods
- Thêm project-specific logic

3. **Separation of Concerns:**

- Core logic trong package
- DB implementation trong project
- Project-specific logic tách biệt

4. **Maintainability:**

- Single source of truth cho core logic
- Dễ update business rules
- Consistent behavior across projects

5. **Flexibility:**

- Dùng bất kỳ DB nào
- Thêm custom validations
- Integrate với các services khác

Bạn cần thêm thông tin về phần nào không?

Tôi sẽ hướng dẫn tạo một auth package sử dụng Poetry. Package này sẽ xử lý authentication và authorization:

### 1. Khởi tạo Project với Poetry

```bash
# Tạo project mới
poetry new auth-core
cd auth-core

# Cấu trúc sau khi tạo:
auth-core/
├── pyproject.toml
├── README.md
├── auth_core/
│   └── __init__.py
└── tests/
    └── __init__.py
```

### 2. Cấu hình Poetry

```toml
# pyproject.toml
[tool.poetry]
name = "auth-core"
version = "0.1.0"
description = "Core authentication package for FastAPI applications"
authors = ["Your Name <your.email@example.com>"]

[tool.poetry.dependencies]
python = "^3.9"
fastapi = "^0.68.0"
python-jose = {extras = ["cryptography"], version = "^3.3.0"}
passlib = {extras = ["bcrypt"], version = "^1.7.4"}
python-multipart = "^0.0.5"
pydantic = {extras = ["email"], version = "^1.8.2"}

[tool.poetry.dev-dependencies]
pytest = "^6.2.5"
pytest-asyncio = "^0.15.1"
black = "^21.7b0"
isort = "^5.9.3"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
```

### 3. Cấu trúc Project

```
auth_core/
├── pyproject.toml
├── README.md
├── auth_core/
│   ├── __init__.py
│   ├── interfaces/
│   │   ├── __init__.py
│   │   └── repository.py    # User repository interface
│   │
│   ├── security/
│   │   ├── __init__.py
│   │   ├── password.py      # Password hashing
│   │   ├── jwt.py          # JWT handling
│   │   └── oauth2.py       # OAuth2 schemas
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   └── auth.py         # Auth business logic
│   │
│   ├── routes/
│   │   ├── __init__.py
│   │   └── auth.py         # Auth endpoints
│   │
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py         # Auth request/response models
│   │   └── user.py         # User models
│   │
│   └── exceptions.py        # Custom exceptions
```

### 4. Implementation Chi tiết

```python
# auth_core/interfaces/repository.py
from typing import Protocol, Optional
from ..schemas.user import UserCreate, UserInDB

class UserRepository(Protocol):
    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        ...

    async def create(self, user: UserCreate) -> UserInDB:
        ...

# auth_core/security/password.py
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# auth_core/security/jwt.py
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt

class JWTHandler:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_access_token(
        self, data: dict, expires_delta: Optional[timedelta] = None
    ) -> str:
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

# auth_core/services/auth.py
from ..interfaces.repository import UserRepository
from ..security.password import verify_password, get_password_hash
from ..security.jwt import JWTHandler
from ..schemas.auth import TokenData
from ..exceptions import InvalidCredentialsException

class AuthService:
    def __init__(
        self,
        repository: UserRepository,
        jwt_handler: JWTHandler
    ):
        self.repository = repository
        self.jwt_handler = jwt_handler

    async def authenticate_user(self, email: str, password: str):
        user = await self.repository.get_by_email(email)
        if not user or not verify_password(password, user.hashed_password):
            raise InvalidCredentialsException()
        return user

    async def create_access_token(self, user_id: int):
        token_data = TokenData(user_id=user_id)
        return self.jwt_handler.create_access_token(data=token_data.dict())

# auth_core/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from ..services.auth import AuthService
from ..schemas.auth import Token

def create_auth_router(auth_service: AuthService) -> APIRouter:
    router = APIRouter()

    @router.post("/token", response_model=Token)
    async def login(form_data: OAuth2PasswordRequestForm = Depends()):
        user = await auth_service.authenticate_user(
            form_data.username,
            form_data.password
        )
        token = await auth_service.create_access_token(user.id)
        return Token(access_token=token, token_type="bearer")

    return router
```

### 5. Sử dụng trong Project

```python
# project/repositories/user.py
from auth_core.interfaces.repository import UserRepository
from auth_core.schemas.user import UserCreate, UserInDB

class PostgresUserRepository(UserRepository):
    def __init__(self, db_session):
        self.db = db_session

    async def get_by_email(self, email: str):
        return await self.db.query(User).filter(User.email == email).first()

    async def create(self, user: UserCreate):
        db_user = User(**user.dict())
        self.db.add(db_user)
        await self.db.commit()
        return UserInDB.from_orm(db_user)

# project/main.py
from fastapi import FastAPI
from auth_core.services.auth import AuthService
from auth_core.routes.auth import create_auth_router
from auth_core.security.jwt import JWTHandler

app = FastAPI()

# Init dependencies
db_session = get_db_session()
user_repo = PostgresUserRepository(db_session)
jwt_handler = JWTHandler(secret_key="your-secret-key")
auth_service = AuthService(repository=user_repo, jwt_handler=jwt_handler)

# Create and include router
auth_router = create_auth_router(auth_service)
app.include_router(auth_router, prefix="/auth", tags=["auth"])
```

### 6. Testing Package

```python
# tests/test_auth_service.py
import pytest
from auth_core.services.auth import AuthService
from auth_core.exceptions import InvalidCredentialsException

@pytest.mark.asyncio
async def test_authenticate_user():
    # Setup mock repository and jwt handler
    mock_repo = MockUserRepository()
    mock_jwt = MockJWTHandler()

    service = AuthService(mock_repo, mock_jwt)

    # Test valid credentials
    user = await service.authenticate_user("test@example.com", "password")
    assert user is not None

    # Test invalid credentials
    with pytest.raises(InvalidCredentialsException):
        await service.authenticate_user("test@example.com", "wrong")
```

### 7. Sử dụng Poetry để Build và Publish

```bash
# Build package
poetry build

# Publish to PyPI
poetry publish

# Hoặc install locally trong development
poetry install
```

Bạn cần thêm thông tin về phần nào không? Ví dụ như:

1. Chi tiết về JWT implementation
2. Cách thêm role-based authorization
3. Cách tích hợp với social auth
4. Testing strategies
5. Cách deploy và sử dụng trong production
