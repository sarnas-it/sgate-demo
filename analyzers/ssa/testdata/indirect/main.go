package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

// sink хранит обработчик как func-значение: AST-модуль такой вызов не
// разрешает, SSA — разрешает по типу.
type sink struct {
	handler func(string) error
}

func (s sink) run(in string) error {
	return s.handler(in)
}

func exec(in string) error {
	_, err := db.Exec(fmt.Sprintf("SELECT * FROM t WHERE name = '%s'", in))
	return err
}

func handler(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("q")
	s := sink{handler: exec}
	if err := s.run(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// safeHandler передаёт ввод параметром, а не склейкой: находки быть не должно.
func safeHandler(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("q")
	if _, err := db.Exec("SELECT * FROM t WHERE name = ?", in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/safe", safeHandler)
}
