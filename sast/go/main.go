package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := "echo hello"
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	fmt.Println(string(out))
}
