"""Unsafe: three request reads the source rule has to recognise structurally.

`sql_request_attribute` next door uses the literal spelling `request.args.get`,
which is the only attribute-chain source shape the corpus had. The rule can
therefore be narrowed a long way without the gate noticing, and narrowing it
fails *open*: a source it stops recognising is a vulnerability it stops
reporting, silently. Each function below is a differently-shaped read that a
narrower rule would drop.
"""

import sqlite3

cursor = sqlite3.connect("app.db").cursor()


def search(http_request):
    """A Flask request object under a name other than `request` or `req`."""
    return cursor.execute(
        "select * from items where name = '" + http_request.args.get("q") + "'"
    )


def by_form(form):
    """Django bound-form data: the *member* names the API, the receiver cannot."""
    return cursor.execute(
        "select * from items where name = '" + form.cleaned_data["name"] + "'"
    )


def wsgi_app(environ, start_response):
    """Bare WSGI: the request is the `environ` mapping itself."""
    return cursor.execute(
        "select * from items where name = '" + environ["QUERY_STRING"] + "'"
    )
