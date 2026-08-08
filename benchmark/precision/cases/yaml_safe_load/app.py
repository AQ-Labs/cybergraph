"""Safe: yaml.safe_load cannot construct arbitrary objects."""

import yaml

from fastapi import FastAPI

app = FastAPI()


@app.post("/config")
def load_config(document: str):
    return yaml.safe_load(document)
