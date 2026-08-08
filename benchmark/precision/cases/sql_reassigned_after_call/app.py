"""Safe: the unsafe query is built *after* the call that runs the safe one."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/notes")
def list_notes(term: str):
    statement = "SELECT id FROM notes"
    cursor.execute(statement)
    statement = "SELECT id FROM notes WHERE body LIKE '" + term + "'"
    return statement
