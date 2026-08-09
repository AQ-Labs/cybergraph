"""Unsafe: a request read written out at the sink, bound to no local.

The other direction of the same rule, and the reason it cannot simply be
narrowed until the lookalikes go quiet. There is no local for the taint map to
answer for, so recognising `request.args.get(...)` structurally is the only
thing between this and a silent miss. Every other case in this corpus takes
taint from a route parameter, which is a different code path entirely.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
cursor = sqlite3.connect("app.db").cursor()


@app.route("/search")
def search():
    return cursor.execute("select * from items where name = '" + request.args.get("q") + "'")
