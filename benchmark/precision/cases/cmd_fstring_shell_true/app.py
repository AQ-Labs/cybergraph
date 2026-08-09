"""Command injection: an f-string command run through a shell."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    subprocess.run(f"ping -c 1 {host}", shell=True, check=False)
