"""Safe: user data arrives as a *context variable*, not as the template."""

from flask import Flask, render_template, render_template_string

app = Flask(__name__)


@app.route("/profile")
def profile(name: str):
    # `render_template` names a template *file*; the tainted value is context.
    render_template("profile.html", name=name)
    # The same distinction at the sink the template predicate actually guards:
    # a literal template, with the tainted value bound as a context variable.
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
