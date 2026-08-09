"""Safe: a pickle of a constant the program itself embedded.

`deserialize`'s only other safe case is `yaml_safe_load`, and `yaml.safe_load`
is absent from the sink registry, so no predicate runs there at all: the class's
two safe-case gates measured the registry and never
`_assess_any_tainted_argument`. Measured -- a mutation making that predicate
report every argument reddened `code` and left `deserialize` green. This case
reaches a registered sink with an argument the predicate has to clear on its
own.
"""

import pickle

from fastapi import FastAPI

app = FastAPI()

DEFAULTS = b"\x80\x04}\x94."


@app.get("/defaults")
def defaults():
    return pickle.loads(b"\x80\x04}\x94.")
