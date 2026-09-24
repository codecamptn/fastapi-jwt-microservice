from datetime import datetime, timedelta
from typing import Optional

import sqlite3
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field


# =========================
# Configuration
# =========================

SECRET_KEY = "change-this-secret-key-before-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

DATABASE = "users.db"


# =========================
# FastAPI Application
# =========================

app = FastAPI(
    title="FastAPI JWT Microservice",
    description="REST API with JWT authentication, validation and SQLite persistence",
    version="1.0.0"
)


# =========================
# Security
# =========================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/login"
)


# =========================
# Database
# =========================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


init_db()


# =========================
# Pydantic Schemas
# =========================

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=100)
    password: str = Field(min_length=6, max_length=100)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: str


class UserUpdate(BaseModel):
    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=50
    )

    email: Optional[str] = Field(
        default=None,
        min_length=5,
        max_length=100
    )


class Token(BaseModel):
    access_token: str
    token_type: str


# =========================
# Helper Functions
# =========================

def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )


def create_access_token(username: str):
    expire = datetime.utcnow() + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": username,
        "exp": expire
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_user_by_username(username: str):
    connection = get_db()

    user = connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    connection.close()

    return user


def get_current_user(
    token: str = Depends(oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = get_user_by_username(username)

    if user is None:
        raise credentials_exception

    return user


# =========================
# Routes
# =========================

@app.get("/")
def home():
    return {
        "message": "FastAPI JWT Microservice is running",
        "docs": "/docs"
    }


@app.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def register(user: UserRegister):

    connection = get_db()

    existing_user = connection.execute(
        """
        SELECT id FROM users
        WHERE username = ? OR email = ?
        """,
        (user.username, user.email)
    ).fetchone()

    if existing_user:
        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        )

    hashed_password = hash_password(user.password)

    created_at = datetime.utcnow().isoformat()

    cursor = connection.execute(
        """
        INSERT INTO users
        (username, email, hashed_password, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            user.username,
            user.email,
            hashed_password,
            created_at
        )
    )

    connection.commit()

    user_id = cursor.lastrowid

    connection.close()

    return {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "created_at": created_at
    }


@app.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends()
):

    user = get_user_by_username(
        form_data.username
    )

    if not user or not verify_password(
        form_data.password,
        user["hashed_password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = create_access_token(
        user["username"]
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get(
    "/users/me",
    response_model=UserResponse
)
def get_profile(
    current_user=Depends(get_current_user)
):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "created_at": current_user["created_at"]
    }


@app.put(
    "/users/me",
    response_model=UserResponse
)
def update_profile(
    user_update: UserUpdate,
    current_user=Depends(get_current_user)
):

    connection = get_db()

    username = (
        user_update.username
        if user_update.username
        else current_user["username"]
    )

    email = (
        user_update.email
        if user_update.email
        else current_user["email"]
    )

    try:
        connection.execute(
            """
            UPDATE users
            SET username = ?, email = ?
            WHERE id = ?
            """,
            (
                username,
                email,
                current_user["id"]
            )
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.close()

        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        )

    updated_user = connection.execute(
        "SELECT * FROM users WHERE id = ?",
        (current_user["id"],)
    ).fetchone()

    connection.close()

    return {
        "id": updated_user["id"],
        "username": updated_user["username"],
        "email": updated_user["email"],
        "created_at": updated_user["created_at"]
    }


@app.delete("/users/me")
def delete_profile(
    current_user=Depends(get_current_user)
):

    connection = get_db()

    connection.execute(
        "DELETE FROM users WHERE id = ?",
        (current_user["id"],)
    )

    connection.commit()
    connection.close()

    return {
        "message": "User deleted successfully"
    }