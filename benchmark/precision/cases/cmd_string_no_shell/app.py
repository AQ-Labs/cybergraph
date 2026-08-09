"""Unknown: a tainted string command with no shell."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/tool")
def run_tool(binary: str):
    subprocess.run(binary, check=False)
