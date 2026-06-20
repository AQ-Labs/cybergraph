package main

import (
	"net/http"
	"os/exec"
)

func runPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	exec.Command("ping", host).Run()
}

func main() {
	http.HandleFunc("/ping", runPing)
	http.ListenAndServe(":8080", nil)
}
