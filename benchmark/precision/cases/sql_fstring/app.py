"""SQL injection: the query text is an f-string over a route parameter."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/users")
def get_user(name: str):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
