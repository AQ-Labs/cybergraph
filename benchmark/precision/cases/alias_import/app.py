"""Known gap: the sink is reached through an aliased module import."""

import subprocess as sp

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    sp.run("ping -c 1 " + host, shell=True, check=False)
