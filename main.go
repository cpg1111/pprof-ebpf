package main

import (
	"fmt"

	"github.com/cpg1111/pprof-ebpf/pkg/cpu"
)

func main() {
	fmt.Println("running pprof-ebpf")

	cpu.Run()
}
