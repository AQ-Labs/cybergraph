"""Safe: eval over a literal expression."""

from fastapi import FastAPI

app = FastAPI()


@app.get("/answer")
def answer():
    return eval("6 * 7")
