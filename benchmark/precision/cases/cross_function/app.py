"""Interprocedural: the route hands user data to a helper that shells out."""

import os

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    return run_ping(host)


def run_ping(host):
    os.system("ping -c 1 " + host)
