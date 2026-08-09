"""Command injection: a list argv that hands the shell inline code."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    subprocess.run(["sh", "-c", "ping -c 1 " + host], check=False)
