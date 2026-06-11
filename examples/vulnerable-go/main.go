// Intentionally vulnerable Go (net/http) demo for CyberGraph.
// It exists so users can see interprocedural attack paths in a compiled
// language: an unauthenticated route reaches a SQL sink through a handler.
package main

import (
	"database/sql"
	"net/http"
	"os"
)

var db *sql.DB

// listUsers is unauthenticated and builds SQL by string concatenation.
func listUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Query("select * from users where name = '" + name + "'") // SQL injection
}

// adminConfig reads a secret from the environment.
func adminConfig() string {
	return os.Getenv("ADMIN_TOKEN")
}

// health is a benign route with no sink.
func health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

func main() {
	http.HandleFunc("/users", listUsers)
	http.HandleFunc("/health", health)
	http.ListenAndServe(":8080", nil)
}
