package main

import (
	"net/http"
	"os"
)

func readFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	os.Open("/data/" + name)
}

func main() {
	http.HandleFunc("/file", readFile)
	http.ListenAndServe(":8080", nil)
}
