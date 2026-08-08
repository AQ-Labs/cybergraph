"""Interprocedural: a sanitising barrier sits between the route and the sink."""

import os

from fastapi import FastAPI

app = FastAPI()
DATA_DIR = "/srv/data"


@app.get("/doc")
def get_doc(name: str):
    return load_doc(name)


def load_doc(name):
    safe_name = sanitize_filename(name)
    with open(os.path.join(DATA_DIR, safe_name)) as handle:
        return handle.read()


def sanitize_filename(value):
    return os.path.basename(value)
