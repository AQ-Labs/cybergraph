"""Code execution: a route parameter is evaluated."""

from fastapi import FastAPI

app = FastAPI()


@app.get("/calc")
def calc(expression: str):
    return eval(expression)
