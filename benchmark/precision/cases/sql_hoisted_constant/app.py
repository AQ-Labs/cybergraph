"""Safe: the query text lives in a module-level constant."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


COUNT_SQL = "SELECT COUNT(*) FROM users"


@app.get("/count")
def count_users():
    cursor.execute(COUNT_SQL)
