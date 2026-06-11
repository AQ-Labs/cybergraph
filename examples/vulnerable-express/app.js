// Intentionally vulnerable Express demo for CyberGraph.
// Shows entrypoints, a SQL sink reached from a route handler, and secret use.
const express = require("express");
const app = express();

// Unauthenticated handler that builds SQL by string concatenation.
function listUsers(req, res) {
  const name = req.query.name;
  db.query("select * from users where name = '" + name + "'"); // SQL injection
  res.send("ok");
}

// Reads a secret from the environment.
function dbUrl() {
  return process.env.DATABASE_URL;
}

app.get("/users", listUsers);
app.get("/health", (req, res) => res.send("ok"));

app.listen(3000);
