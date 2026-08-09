"""Safe: a wholly constant command."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/uptime")
def uptime():
    subprocess.run(["uptime"], check=False)
