"""Deserialization: a request body is unpickled."""

import base64
import pickle

from fastapi import FastAPI

app = FastAPI()


@app.post("/state")
def load_state(blob: str):
    return pickle.loads(base64.b64decode(blob))
