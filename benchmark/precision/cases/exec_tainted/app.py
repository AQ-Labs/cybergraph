"""Code execution: a request body is exec'd."""

from fastapi import FastAPI

app = FastAPI()


@app.post("/script")
def run_script(source: str):
    exec(source)  # noqa: S102
    return "ok"
