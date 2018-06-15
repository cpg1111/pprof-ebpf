package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cpg1111/pprof-ebpf/cmd"
)

func main() {
	if os.Getuid() != 0 {
		cmd := exec.Command("sudo", os.Args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			os.Exit(1)
		}
	}
	fmt.Println("running pprof-ebpf")
	cmd.Execute()
}
