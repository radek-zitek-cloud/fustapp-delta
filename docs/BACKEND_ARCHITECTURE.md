# Python Backend Architecture - REST & GraphQL API Server

## Core Architecture Overview

### Framework Selection

- **Primary Framework**: FastAPI
  - Native async/await support for high performance
  - Automatic OpenAPI documentation generation
  - Built-in dependency injection
  - Excellent validation with Pydantic
  - Easy integration with both REST and GraphQL

### Application Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py         # Environment-based configuration
│   │   └── database.py         # Database connection setup
│   ├── core/
│   │   ├── __init__.py
│   │   ├── auth.py            # Authentication logic
│   │   ├── dependencies.py    # FastAPI dependencies
│   │   ├── exceptions.py      # Custom exception handlers
│   │   └── middleware.py      # Custom middleware
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py            # SQLAlchemy base model
│   │   ├── user.py            # User model
│   │   └── ...                # Other domain models
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── user.py            # Pydantic schemas for validation
│   │   └── ...                # Other schema definitions
│   ├── repositories/
│   │   ├── __init__.py
│   │   ├── base.py            # Base repository pattern
│   │   ├── user.py            # User repository
│   │   └── ...                # Other repositories
│   ├── services/
│   │   ├── __init__.py
│   │   ├── user.py            # Business logic for users
│   │   └── ...                # Other business services
│   ├── api/
│   │   ├── __init__.py
│   │   ├── rest/
│   │   │   ├── __init__.py
│   │   │   ├── v1/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── router.py  # Main REST router
│   │   │   │   ├── users.py   # User endpoints
│   │   │   │   └── ...        # Other REST endpoints
│   │   └── graphql/
│   │       ├── __init__.py
│   │       ├── schema.py      # GraphQL schema definition
│   │       ├── resolvers/
│   │       │   ├── __init__.py
│   │       │   ├── user.py    # User resolvers
│   │       │   └── ...        # Other resolvers
│   │       └── types/
│   │           ├── __init__.py
│   │           ├── user.py    # GraphQL types
│   │           └── ...        # Other GraphQL types
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── security.py        # Security utilities
│   │   ├── helpers.py         # General helper functions
│   │   └── validators.py      # Custom validators
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py        # Pytest configuration
│       ├── test_api/
│       │   ├── test_rest/
│       │   └── test_graphql/
│       ├── test_services/
│       └── test_repositories/
├── migrations/                 # Alembic migrations
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.dev.yml
├── requirements/
│   ├── base.txt
│   ├── dev.txt
│   └── prod.txt
├── scripts/
│   ├── run_dev.py
│   └── run_migrations.py
└── pyproject.toml
```

## Technology Stack

### Core Dependencies

- **FastAPI**: Web framework
- **Strawberry GraphQL**: Modern GraphQL library for Python
- **SQLAlchemy 2.0**: ORM with async support
- **Alembic**: Database migrations
- **Pydantic**: Data validation and serialization
- **asyncpg**: PostgreSQL async driver
- **Redis**: Caching and session storage

### Additional Libraries

- **python-jose[cryptography]**: JWT handling
- **passlib[bcrypt]**: Password hashing
- **python-multipart**: File upload support
- **uvicorn[standard]**: ASGI server
- **gunicorn**: Production WSGI server

## Database Layer

### Database Configuration

```python
# config/database.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

DATABASE_URL = "postgresql+asyncpg://user:password@localhost/dbname"

engine = create_async_engine(
    DATABASE_URL,
    echo=True,
    pool_size=20,
    max_overflow=0,
    pool_pre_ping=True
)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()
```

### Repository Pattern

```python
# repositories/base.py
from typing import Generic, TypeVar, Type, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload

ModelType = TypeVar("ModelType", bound=Base)

class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], db: AsyncSession):
        self.model = model
        self.db = db

    async def get(self, id: int) -> Optional[ModelType]:
        result = await self.db.execute(select(self.model).where(self.model.id == id))
        return result.scalar_one_or_none()

    async def get_multi(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        result = await self.db.execute(select(self.model).offset(skip).limit(limit))
        return result.scalars().all()

    async def create(self, obj_in: dict) -> ModelType:
        db_obj = self.model(**obj_in)
        self.db.add(db_obj)
        await self.db.commit()
        await self.db.refresh(db_obj)
        return db_obj
```

## API Layer Design

### REST API Structure

```python
# api/rest/v1/router.py
from fastapi import APIRouter, Depends, HTTPException
from app.services.user import UserService
from app.schemas.user import UserCreate, UserResponse
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/v1")

@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    user_service: UserService = Depends()
):
    return await user_service.create_user(user_data)

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user = Depends(get_current_user)
):
    user_service = UserService()
    return await user_service.get_user(user_id)
```

### GraphQL Schema

```python
# api/graphql/schema.py
import strawberry
from typing import List, Optional
from app.api.graphql.types.user import User
from app.api.graphql.resolvers.user import UserResolver

@strawberry.type
class Query:
    @strawberry.field
    async def users(self, info) -> List[User]:
        resolver = UserResolver()
        return await resolver.get_users(info)

    @strawberry.field
    async def user(self, info, id: int) -> Optional[User]:
        resolver = UserResolver()
        return await resolver.get_user(info, id)

@strawberry.type
class Mutation:
    @strawberry.field
    async def create_user(self, info, name: str, email: str) -> User:
        resolver = UserResolver()
        return await resolver.create_user(info, name, email)

schema = strawberry.Schema(query=Query, mutation=Mutation)
```

## Authentication & Authorization

### JWT Implementation

```python
# core/auth.py
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
```

## Caching Strategy

### Redis Integration

```python
# core/cache.py
import redis.asyncio as redis
import json
from typing import Any, Optional
from app.config.settings import settings

class CacheService:
    def __init__(self):
        self.redis = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )

    async def get(self, key: str) -> Optional[Any]:
        value = await self.redis.get(key)
        if value:
            return json.loads(value)
        return None

    async def set(self, key: str, value: Any, expire: int = 3600):
        await self.redis.set(key, json.dumps(value), ex=expire)

    async def delete(self, key: str):
        await self.redis.delete(key)
```

## Main Application Setup

### FastAPI Application

```python
# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from strawberry.fastapi import GraphQLRouter
from app.api.rest.v1.router import router as rest_router
from app.api.graphql.schema import schema
from app.core.middleware import LoggingMiddleware

app = FastAPI(
    title="Backend API",
    description="REST and GraphQL API Server",
    version="1.0.0"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)

# REST API routes
app.include_router(rest_router)

# GraphQL endpoint
graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
```

## API Documentation & Development Tools

### Swagger UI Configuration

FastAPI automatically generates OpenAPI documentation and provides Swagger UI out of the box. Here's how to configure and customize it:

```python
# main.py (enhanced version)
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from strawberry.fastapi import GraphQLRouter

app = FastAPI(
    title="FustApp Delta Backend API",
    description="""
    ## REST and GraphQL API Server
    
    This API provides comprehensive backend functionality including:
    
    * **User Management** - Complete CRUD operations for users
    * **Authentication** - JWT-based authentication system
    * **Authorization** - Role-based access control (RBAC)
    * **REST API** - RESTful endpoints following OpenAPI standards
    * **GraphQL API** - Flexible GraphQL interface for complex queries
    
    ### Available Endpoints
    
    * **REST API Documentation**: `/docs` (Swagger UI)
    * **Alternative REST Docs**: `/redoc` (ReDoc)
    * **GraphQL Playground**: `/graphql` (Interactive GraphQL IDE)
    * **OpenAPI Schema**: `/openapi.json`
    """,
    version="1.0.0",
    contact={
        "name": "FustApp Development Team",
        "email": "dev@fustapp.com",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    # Enable/disable docs based on environment
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
)

# Custom OpenAPI schema with security definitions
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="FustApp Delta API",
        version="1.0.0",
        description="Comprehensive backend API with REST and GraphQL endpoints",
        routes=app.routes,
    )
    
    # Add security schemes for JWT authentication
    openapi_schema["components"]["securitySchemes"] = {
        "Bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter JWT token"
        }
    }
    
    # Add server information
    openapi_schema["servers"] = [
        {"url": "http://localhost:8000", "description": "Development server"},
        {"url": "https://api.fustapp.com", "description": "Production server"},
    ]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

### Enhanced REST API Documentation

```python
# api/rest/v1/users.py
from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services.user import UserService
from app.core.dependencies import get_current_user

router = APIRouter(prefix="/users", tags=["Users"])
security = HTTPBearer()

@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user",
    description="Create a new user account with email verification",
    responses={
        201: {
            "description": "User created successfully",
            "model": UserResponse
        },
        400: {
            "description": "Invalid input data",
            "content": {
                "application/json": {
                    "example": {"detail": "Email already registered"}
                }
            }
        },
        422: {
            "description": "Validation error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": [
                            {
                                "loc": ["body", "email"],
                                "msg": "field required",
                                "type": "value_error.missing"
                            }
                        ]
                    }
                }
            }
        }
    }
)
async def create_user(
    user_data: UserCreate,
    user_service: UserService = Depends()
):
    """
    Create a new user with the following information:
    
    - **name**: User's full name (required)
    - **email**: Valid email address, must be unique (required)
    - **password**: Strong password, minimum 8 characters (required)
    - **role**: User role (optional, defaults to 'user')
    
    Returns the created user data with generated ID and timestamps.
    """
    try:
        return await user_service.create_user(user_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description="Retrieve user information by user ID. Requires authentication.",
    responses={
        200: {"description": "User found", "model": UserResponse},
        401: {"description": "Authentication required"},
        403: {"description": "Access denied"},
        404: {"description": "User not found"},
    }
)
async def get_user(
    user_id: int,
    current_user = Depends(get_current_user),
    user_service: UserService = Depends(),
    token: str = Security(security)
):
    """
    Get user information by ID.
    
    **Authentication Required**: Provide Bearer token in Authorization header.
    
    - **user_id**: The unique identifier of the user to retrieve
    
    Returns complete user information if authorized.
    """
    return await user_service.get_user(user_id, current_user)

@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user",
    description="Update user information. Users can only update their own data unless they have admin privileges."
)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user = Depends(get_current_user),
    user_service: UserService = Depends()
):
    """Update user information with provided data."""
    return await user_service.update_user(user_id, user_data, current_user)
```

### GraphQL Playground Configuration

```python
# api/graphql/schema.py
import strawberry
from strawberry.fastapi import GraphQLRouter
from typing import List, Optional
from app.api.graphql.types.user import User
from app.api.graphql.resolvers.user import UserResolver

@strawberry.type
class Query:
    """
    Root Query type for GraphQL API
    
    Provides read access to all available data through the GraphQL interface.
    """
    
    @strawberry.field(description="Get paginated list of users")
    async def users(
        self, 
        info,
        skip: int = strawberry.field(default=0, description="Number of records to skip"),
        limit: int = strawberry.field(default=10, description="Maximum records to return (max: 100)")
    ) -> List[User]:
        """
        Retrieve a paginated list of users.
        
        Example Query:
        ```graphql
        query GetUsers {
          users(skip: 0, limit: 5) {
            id
            name
            email
            role
            isActive
            createdAt
          }
        }
        ```
        """
        resolver = UserResolver()
        return await resolver.get_users(info, skip, min(limit, 100))

    @strawberry.field(description="Get user by unique ID")
    async def user(
        self, 
        info, 
        id: int = strawberry.field(description="User's unique identifier")
    ) -> Optional[User]:
        """
        Retrieve a specific user by their ID.
        
        Example Query:
        ```graphql
        query GetUser {
          user(id: 1) {
            id
            name
            email
            profile {
              firstName
              lastName
              avatar
            }
          }
        }
        ```
        """
        resolver = UserResolver()
        return await resolver.get_user(info, id)

    @strawberry.field(description="Search users by name or email")
    async def searchUsers(
        self,
        info,
        query: str = strawberry.field(description="Search term for name or email"),
        limit: int = strawberry.field(default=10, description="Maximum results to return")
    ) -> List[User]:
        """
        Search for users by name or email.
        
        Example Query:
        ```graphql
        query SearchUsers {
          searchUsers(query: "john", limit: 5) {
            id
            name
            email
          }
        }
        ```
        """
        resolver = UserResolver()
        return await resolver.search_users(info, query, limit)

@strawberry.type
class Mutation:
    """
    Root Mutation type for GraphQL API
    
    Provides write operations for modifying data through the GraphQL interface.
    """
    
    @strawberry.field(description="Create a new user account")
    async def createUser(
        self, 
        info, 
        input: "UserCreateInput"
    ) -> User:
        """
        Create a new user account.
        
        Example Mutation:
        ```graphql
        mutation CreateUser {
          createUser(input: {
            name: "John Doe"
            email: "john@example.com"
            password: "securePassword123"
          }) {
            id
            name
            email
            createdAt
          }
        }
        ```
        """
        resolver = UserResolver()
        return await resolver.create_user(info, input)

    @strawberry.field(description="Update existing user information")
    async def updateUser(
        self,
        info,
        id: int = strawberry.field(description="User ID to update"),
        input: "UserUpdateInput" = strawberry.field(description="Updated user data")
    ) -> User:
        """
        Update user information.
        
        Example Mutation:
        ```graphql
        mutation UpdateUser {
          updateUser(id: 1, input: {
            name: "John Smith"
            email: "johnsmith@example.com"
          }) {
            id
            name
            email
            updatedAt
          }
        }
        ```
        """
        resolver = UserResolver()
        return await resolver.update_user(info, id, input)

# Input types for mutations
@strawberry.input
class UserCreateInput:
    name: str = strawberry.field(description="User's full name")
    email: str = strawberry.field(description="Valid email address")
    password: str = strawberry.field(description="Password (min 8 characters)")
    role: Optional[str] = strawberry.field(default="user", description="User role")

@strawberry.input
class UserUpdateInput:
    name: Optional[str] = strawberry.field(default=None, description="Updated name")
    email: Optional[str] = strawberry.field(default=None, description="Updated email")
    is_active: Optional[bool] = strawberry.field(default=None, description="Account status")

# Create schema with introspection enabled for development
schema = strawberry.Schema(
    query=Query, 
    mutation=Mutation,
    description="FustApp Delta GraphQL API - Comprehensive backend interface"
)

# GraphQL Router configuration
def create_graphql_router():
    """Create GraphQL router with appropriate settings"""
    return GraphQLRouter(
        schema,
        graphiql=settings.ENVIRONMENT != "production",  # Enable GraphiQL in non-prod
        introspection=settings.ENVIRONMENT != "production",  # Enable introspection in non-prod
        debug=settings.DEBUG,
    )
```

### Development Tools Access

#### Swagger UI Features

When running in development mode, access the following documentation endpoints:

- **Swagger UI**: `http://localhost:8000/docs`
  - Interactive API documentation
  - Test API endpoints directly from browser
  - Authentication support with JWT tokens
  - Request/response examples
  - Schema validation

- **ReDoc**: `http://localhost:8000/redoc`
  - Alternative documentation interface
  - Better for API reference documentation
  - Clean, organized layout

#### GraphQL Playground Features

Access GraphQL Playground at: `http://localhost:8000/graphql`

**Key Features:**

- Interactive query builder with syntax highlighting
- Schema explorer with type definitions
- Query history and saved queries
- Real-time query validation
- Subscription support (when implemented)
- Variables and headers management

**Example GraphQL Queries:**

```graphql
# Query with variables
query GetUserWithPosts($userId: Int!, $postsLimit: Int = 5) {
  user(id: $userId) {
    id
    name
    email
    posts(limit: $postsLimit) {
      id
      title
      content
      createdAt
    }
  }
}

# Complex mutation
mutation CreateUserWithProfile {
  createUser(input: {
    name: "Jane Doe"
    email: "jane@example.com"
    password: "securePass123"
  }) {
    id
    name
    email
    profile {
      firstName
      lastName
    }
    createdAt
  }
}
```

### Security Configuration for Documentation

```python
# config/settings.py (additions)
class Settings(BaseSettings):
    # ...existing code...

    # Documentation settings
    ENABLE_DOCS: bool = True
    DOCS_USERNAME: Optional[str] = None  # Basic auth for docs in production
    DOCS_PASSWORD: Optional[str] = None

# Optional: Secure documentation in production
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

security_basic = HTTPBasic()

def authenticate_docs(credentials: HTTPBasicCredentials = Depends(security_basic)):
    """Basic authentication for documentation endpoints in production"""
    if settings.ENVIRONMENT == "production":
        correct_username = secrets.compare_digest(
            credentials.username, settings.DOCS_USERNAME or ""
        )
        correct_password = secrets.compare_digest(
            credentials.password, settings.DOCS_PASSWORD or ""
        )
        if not (correct_username and correct_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )
    return credentials

# Apply to documentation routes if needed
if settings.ENVIRONMENT == "production" and settings.DOCS_USERNAME:
    app.docs_url = None
    app.redoc_url = None
    
    @app.get("/docs", include_in_schema=False)
    async def get_docs(credentials: HTTPBasicCredentials = Depends(authenticate_docs)):
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")
```

This comprehensive setup provides developers with powerful tools for API development, testing, and documentation while maintaining security considerations for production environments.

## Testing Strategy

### Test Configuration

```python
# tests/conftest.py
import pytest
import asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.config.database import get_db, Base

# Test database setup
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost/test_db"

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def test_db():
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, class_=AsyncSession)

    async with async_session() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture
def client(test_db):
    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as c:
        yield c
```

## Production Deployment

### Docker Configuration

```dockerfile
# docker/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements/prod.txt .
RUN pip install --no-cache-dir -r prod.txt

COPY . .

EXPOSE 8000

CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
```

### Environment Configuration

```python
# config/settings.py
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # Auth
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # CORS
    ALLOWED_HOSTS: list[str] = ["*"]

    class Config:
        env_file = ".env"

settings = Settings()
```

## Monitoring & Observability

### Logging Configuration

```python
# core/middleware.py
import logging
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Log request
        logger.info(f"Request: {request.method} {request.url}")

        response = await call_next(request)

        # Log response
        process_time = time.time() - start_time
        logger.info(
            f"Response: {response.status_code} "
            f"Time: {process_time:.2f}s"
        )

        return response
```

## Performance Optimization

### Connection Pooling & Caching

- **Database**: SQLAlchemy connection pooling with configurable pool size
- **Redis**: Connection pooling for cache operations
- **Background Tasks**: Celery integration for async task processing
- **Response Caching**: Strategic caching of expensive operations

### Scalability Considerations

- **Horizontal Scaling**: Stateless design with external session storage
- **Load Balancing**: Support for multiple application instances
- **Database**: Read replicas and query optimization
- **CDN Integration**: Static asset optimization

## Security Features

### Implementation Details

- **Input Validation**: Pydantic schemas for all API inputs
- **SQL Injection Prevention**: SQLAlchemy ORM usage
- **CORS Configuration**: Configurable origin restrictions
- **Rate Limiting**: Redis-based rate limiting middleware
- **Security Headers**: HTTPS enforcement and security headers
- **API Versioning**: Versioned REST endpoints for backward compatibility

This architecture provides a robust foundation for a Python backend serving both REST and GraphQL APIs, with emphasis on maintainability, scalability, and developer experience.
