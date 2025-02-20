# FastAPI Auth Core

A powerful authentication and authorization library for FastAPI applications, simplifying the implementation of secure authentication and permission systems in web applications.

## 🌟 Key Features

### 🔐 Authentication

- Flexible authentication system with JWT (JSON Web Tokens)
- Built-in OAuth2 integration with multiple providers
- Multi-factor authentication support (MFA/2FA)
- Session and token management

### 👥 Authorization

- Flexible Role-Based Access Control (RBAC) system
- Fine-grained resource-level permissions
- Simple decorators for API endpoint protection
- Built-in middleware for permission management

### 🛡️ Security

- Industry-standard password encryption
- Protection against brute-force attacks
- Integrated rate limiting
- Security best practices implementation

## 📦 Installation

```bash
pip install fastapi-auth-core
```

## 🚀 Quick Start

### Service Configuration

```python
from fastapi import FastAPI
from auth_core import requires_permissions
from auth_core.services.auth import AuthService
from auth_core.security.jwt import JWTHandler

app = FastAPI()

@app.on_event("startup")
async def startup():
    user_repo = PostgresUserRepository()
    role_repo = PostgresRoleRepository()
    permission_repo = PostgresPermissionRepository()

    jwt_handler = JWTHandler(secret_key="your-secret-key")

    AuthService(
        user_repository=user_repo,
        role_repository=role_repo,
        permission_repository=permission_repo,
        jwt_handler=jwt_handler,
        token_expire_minutes=30
    )
```

### Protecting Endpoints

```python
from auth_core import requires_permissions

@app.get("/users")
@requires_permissions(["users:read"])
async def get_users():
    return {"message": "Access granted to read users"}

@app.post("/users")
@requires_permissions(["users:create"])
async def create_user():
    return {"message": "Access granted to create user"}
```

## 📚 Documentation

For detailed documentation and advanced guides, visit our [documentation](docs/).

## 🤝 Contributing

We welcome contributions from the community! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.
