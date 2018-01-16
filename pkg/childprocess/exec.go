package childprocess

import (
	"os/exec"
	"strings"
)

// Exec executes a commmand as a child process and returns either
// the child process' pid or an error
func Exec(cmd string) (int, error) {
	args := strings.Split(cmd, " ")
	child := exec.Command(args[0], args...)
	err := child.Start()
	if err != nil {
		return -1, err
	}
	return child.Process.Pid, nil
}
