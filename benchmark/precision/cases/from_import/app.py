"""Known gap: the sink is reached through a from-import."""

from subprocess import run

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    run("ping -c 1 " + host, shell=True, check=False)
