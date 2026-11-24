// sgatedast — discovery целей DAST в согласованном scope.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"code.sarnas.ru/sgate/internal/dast"
)

func main() {
	scopePath := flag.String("scope", "dast/scope.example.yaml", "путь к scope")
	out := flag.String("out", "", "записать URL в файл")
	flag.Parse()

	scope, err := dast.Load(*scopePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sgatedast:", err)
		os.Exit(2)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	urls, err := dast.Discover(context.Background(), client, scope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sgatedast:", err)
		os.Exit(2)
	}
	for _, u := range urls {
		fmt.Println(u)
	}
	fmt.Fprintf(os.Stderr, "найдено целей: %d, scope: %s\n", len(urls), scope.Target)
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "sgatedast:", err)
			os.Exit(2)
		}
		var b []byte
		for _, u := range urls {
			b = append(b, []byte(u+"\n")...)
		}
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "sgatedast:", err)
			os.Exit(2)
		}
	}
}
