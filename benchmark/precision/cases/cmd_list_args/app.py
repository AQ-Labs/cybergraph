"""Safe: user data is a positional argument to a program that runs no code."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/show")
def show_revision(revision: str):
    subprocess.run(["git", "show", revision], check=False)
