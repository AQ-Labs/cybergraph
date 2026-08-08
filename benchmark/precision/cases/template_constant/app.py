"""Safe: a wholly constant template."""

from flask import Flask, render_template_string

app = Flask(__name__)


@app.route("/banner")
def banner():
    return render_template_string("<p>Service is running.</p>")
