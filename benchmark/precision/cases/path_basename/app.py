"""Safe: os.path.basename confines the path to one directory."""

import os

from fastapi import FastAPI

app = FastAPI()
DATA_DIR = "/srv/data"


@app.get("/file")
def read_file(name: str):
    with open(os.path.join(DATA_DIR, os.path.basename(name))) as handle:
        return handle.read()
