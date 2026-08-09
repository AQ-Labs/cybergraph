"""SQL injection: the query text is built with str.format."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/users")
def get_user(name: str):
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
