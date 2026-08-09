"""Path traversal: the route parameter is concatenated into the path."""

import os

from fastapi import FastAPI

app = FastAPI()
DATA_DIR = "/srv/data"


@app.get("/file")
def read_file(name: str):
    with open("/srv/data/" + name) as handle:
        return handle.read()
