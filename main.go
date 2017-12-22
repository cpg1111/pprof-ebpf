package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/cpg1111/pprof-ebpf/pkg/cpu"
)

var pid = flag.Int("pid", 1, "pid to profile")

func main() {
	fmt.Println("running pprof-ebpf")
	err := cpu.Run(*pid, 0, 0, 99999, 256, 1024, 0, false, false, false)
	if err != nil {
		log.Fatal(err)
	}
}
