"""Template injection: user data is concatenated into the template text."""

from flask import Flask, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello(name: str):
    return render_template_string("<h1>Hello " + name + "</h1>")
