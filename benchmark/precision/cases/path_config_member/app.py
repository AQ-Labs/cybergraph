"""Safe: a config object's member whose name merely contains a source word.

`cfg.input_dir` is not a read of user input, and nothing on this path comes
from the request. Substring-matching the dotted chain against SOURCE_KEYWORDS
made it one, and this a `CG-PATH-TRAVERSAL` high.
"""

import os

from fastapi import FastAPI

from settings import cfg

app = FastAPI()


@app.get("/banner")
def banner():
    with open(os.path.join(cfg.input_dir, "banner.txt")) as handle:
        return handle.read()
