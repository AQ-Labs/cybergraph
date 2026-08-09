"""Unknown: normpath canonicalises without confining."""

import os

from fastapi import FastAPI

app = FastAPI()
DATA_DIR = "/srv/data"


@app.get("/file")
def read_file(name: str):
    target = os.path.normpath(os.path.join(DATA_DIR, name))
    with open(target) as handle:
        return handle.read()
