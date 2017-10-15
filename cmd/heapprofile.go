package cmd

import (
	"github.com/spf13/cobra"
)

var heapprofileCMD = &cobra.Command{
	Usage: "pprof-ebpf [OPTIONS] heapprofile [SUBOPTIONS]",
	Short: "profile heap allocations",
	Long: `profile heap allocations in user space and/or kernel space
	for a specific pid or binary`,
	Run: func(cmd *cobra.Comman, args []string) {

	},
}
