"""Safe: the same lookalike at the severity that hurts most.

`cfg.input_dir` reaching a `shell=True` command scored `CG-CMD-EXEC` critical
purely because the member name contains `input`. A critical on a config object
is the shape that fills a code-scanning tab with noise.
"""

import subprocess

from fastapi import FastAPI

from settings import cfg

app = FastAPI()


@app.get("/listing")
def listing():
    return subprocess.run("ls " + cfg.input_dir, shell=True, check=False)
