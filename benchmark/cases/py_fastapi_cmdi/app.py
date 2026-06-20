import subprocess

from fastapi import FastAPI

app = FastAPI()


def run_ping(host):
    return subprocess.run("ping " + host, shell=True)


@app.get("/ping")
def ping(host: str):
    return run_ping(host)
