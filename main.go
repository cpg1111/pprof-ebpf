package main

import (
	//"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	//"github.com/cpg1111/pprof-ebpf/pkg/cpu"
	"github.com/cpg1111/pprof-ebpf/pkg/heap"
)

//var pid = flag.Int("pid", 1, "pid to profile")

func main() {
	fmt.Println("running pprof-ebpf")
	/*err := cpu.Run(*pid, 0, 0, 99999, 256, 1024, 0, false, false, false)
	if err != nil {
		log.Fatal(err)
	}*/
	cmdPath := fmt.Sprintf("%ssrc/github.com/cpg1111/pprof-ebpf/test_prog/c/test_c", os.Getenv("GOPATH"))
	cmd := exec.Command(cmdPath)
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
	err = heap.Run(cmd.Process.Pid, 0, 4096, 3, 100, false, false, true, "c")
	if err != nil {
		syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
		log.Fatal(err)
	}
}
