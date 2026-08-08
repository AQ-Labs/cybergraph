"""Command injection: the attacker picks the executable."""

import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/tool")
def run_tool(program: str):
    subprocess.run([program, "--version"], check=False)
