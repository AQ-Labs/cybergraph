"""Safe: a wholly constant query."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/count")
def count_users():
    cursor.execute("SELECT COUNT(*) FROM users")
