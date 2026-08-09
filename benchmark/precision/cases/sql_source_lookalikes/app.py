"""Safe: three shapes that only look like a read of user input.

The other direction of `sql_source_shapes`. Widening a source rule until every
renamed request object is recognised is easy; doing it without dragging these
in is the actual constraint, and none of them was visible to the corpus before.
Every one produced a confirmed `CG-SQL-EXEC` at some point in this module's
history.
"""

import sqlite3

import requests

cursor = sqlite3.connect("app.db").cursor()
session = requests.Session()

DEFAULTS = {"pending": "pending", "done": "done"}


def query(name):
    """An ordinary local helper that happens to be called `query`."""
    return DEFAULTS[name]


def sync_status():
    """An *outbound* HTTP call. `.text` is a response, not an inbound request."""
    status = session.request("GET", "https://api.example.com/status").text
    return cursor.execute("select * from jobs where status = '" + status + "'")


def lookup(name):
    """A bare call named after a source keyword is not a source factory."""
    value = query(name)
    return cursor.execute("select * from jobs where status = '" + value + "'")


class Poller:
    def poll(self):
        """An HTTP *client* wrapper: `.timeout` is a setting, not a payload."""
        return cursor.execute(
            "select * from jobs where deadline = '" + self.request.timeout + "'"
        )
