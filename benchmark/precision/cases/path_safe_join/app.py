"""Safe: werkzeug's safe_join confines the path."""

import os

from fastapi import FastAPI

app = FastAPI()
DATA_DIR = "/srv/data"


from werkzeug.utils import safe_join  # noqa: E402


@app.get("/file")
def read_file(name: str):
    with open(safe_join(DATA_DIR, name)) as handle:
        return handle.read()
