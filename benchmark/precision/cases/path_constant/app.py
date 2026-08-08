"""Safe: a wholly constant path."""

import os

from fastapi import FastAPI

app = FastAPI()
DATA_DIR = "/srv/data"


@app.get("/version")
def version():
    with open("/srv/data/version.txt") as handle:
        return handle.read()
