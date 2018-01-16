package main

import (
	"fmt"

	"github.com/cpg1111/pprof-ebpf/cmd"
)

func main() {
	fmt.Println("running pprof-ebpf")
	cmd.Execute()
}
