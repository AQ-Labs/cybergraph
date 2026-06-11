package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func listUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Query("select * from users where name = '" + name + "'")
}

func main() {
	http.HandleFunc("/users", listUsers)
	http.ListenAndServe(":8080", nil)
}
