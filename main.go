package main

import (
	"flag"
	"fmt"

	"github.com/cpg1111/pprof-ebpf/pkg/cpu"
)

var pid = flag.Int("pid", 1, "pid to profile")

func main() {
	fmt.Println("running pprof-ebpf")

	err := cpu.Run(*pid, 0, 0, 99999, 4096, 1024, 0, false, false, false)
	fmt.Println(err)
}
