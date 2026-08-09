"""Unknown: the query text comes back from a helper we cannot see into."""

import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


from queries import build_search  # noqa: E402


@app.get("/search")
def search(term: str):
    statement = build_search(term)
    cursor.execute(statement)
