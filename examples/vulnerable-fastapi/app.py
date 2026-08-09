import sqlite3

from fastapi import Depends, FastAPI, Request

app = FastAPI()


def require_admin(request: Request) -> bool:
    token = request.headers.get("authorization")
    return token == "Bearer dev-admin-token"


def validate_name(name: str) -> str:
    return name.strip()


def raw_sql(query: str) -> list[dict]:
    # A real sink, so the example demonstrates something. It used to be a stub
    # that only got reported because the old matcher saw "raw" in "raw_sql".
    return sqlite3.connect("app.db").execute(query).fetchall()


@app.get("/users")
def list_users(name: str, _admin: bool = Depends(require_admin)) -> list[dict]:
    safe_name = validate_name(name)
    query = f"select * from users where name = '{safe_name}'"
    return raw_sql(query)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
