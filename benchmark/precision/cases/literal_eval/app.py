"""Safe: ast.literal_eval parses literals and runs nothing."""

import ast

from fastapi import FastAPI

app = FastAPI()


@app.get("/parse")
def parse_value(value: str):
    return ast.literal_eval(value)
