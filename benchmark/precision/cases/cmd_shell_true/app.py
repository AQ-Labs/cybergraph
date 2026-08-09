"""Command injection: a concatenated string run through a shell."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    subprocess.run("ping -c 1 " + host, shell=True, check=False)
