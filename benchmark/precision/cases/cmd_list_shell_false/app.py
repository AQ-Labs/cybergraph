"""Safe: the same shape with shell=False stated explicitly."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/log")
def show_log(path: str):
    subprocess.run(["git", "log", "--oneline", path], shell=False, check=False)
