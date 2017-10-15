package cmd

import (
	"github.com/spf13/cobra"
)

var cpuprofileCMD = &cobra.Command{
	Usage: "pprof-ebpf [OPTIONS] cpuprofile [SUBOPTIONS]",
	Short: "profile cpu",
	Long: `profile cpu in user space and/or kernel space
	for a specific pid or binary`,
	Run: func(cmd *cobra.Comman, args []string) {

	},
}
