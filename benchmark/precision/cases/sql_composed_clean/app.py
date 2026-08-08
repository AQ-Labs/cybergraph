"""Safe: the query text is composed, but from no user data."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


REPORT_TABLES = ("users", "sessions")


@app.get("/report")
def report(page: int):
    table = REPORT_TABLES[0]
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
