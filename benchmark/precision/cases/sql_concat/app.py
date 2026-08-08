"""SQL injection: the query text is concatenated from a route parameter."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/users")
def get_user(name: str):
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
