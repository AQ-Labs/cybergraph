from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/users")
def users():
    name = request.args.get("name")
    return run_query(name)


def run_query(name):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"select * from users where name = '{name}'").fetchall()


def verify_token(token):
    return token == "dev-token"
