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

### Middleware Configuration

```python
from fastapi import FastAPI
from auth_core import PermissionMiddleware, AuthService

app = FastAPI()

# Initialize auth service
auth_service = AuthService()

# Configure middleware
permission_middleware = PermissionMiddleware()
permission_middleware.configure(
    auth_service=auth_service,
    get_current_user=auth_service.get_current_user
)

# Add middleware to application
app.add_middleware(permission_middleware)
```

### Protecting Endpoints

```python
from auth_core import requires_permissions

@app.get("/users")
@requires_permissions(["users:read"])
async def get_users():
    return {"message": "Access granted"}

@app.post("/users")
@requires_permissions(["users:create"])
async def create_user(user_data: UserCreate):
    return {"message": "User created"}
```

## 📚 Documentation

For detailed documentation and advanced guides, visit our [documentation](docs/).

## 🤝 Contributing

We welcome contributions from the community! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.
