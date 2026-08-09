"""SQL injection: the query text is extended with += before execution."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/notes")
def search_notes(term: str):
    statement = "SELECT id FROM notes WHERE body LIKE '"
    statement += term
    cursor.execute(statement + "'")
