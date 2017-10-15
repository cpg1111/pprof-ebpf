package cmd

import (
	"github.com/spf13/cobra"
)

func Execute() {
	rootCMD = &cobra.Command{
		Use:   "pprof-ebpf [OPTION] [SUBCOMMAND] [SUBOPTIONS]",
		Short: "A profiler using ebpf that produces pprof format profiles",
		Long: `A profiler that uses ebpf for user and kernel space tracing
		and outputs pprof (https://github.com/google/pprof) format
		profile so that one can generate the same visualizations
		one could generate with tools such as go's runtime/pprof.
		
		View full documentation at: https://github.com/cpg1111/pprof-ebpf`,
		Run: func(cmd *cobra.Command, args []string) {

		},
	}
	rootCMD.AddCommand(cpuprofileCMD)
	rootCMD.AddCommand(heapprofileCMD)

	rootCmd.Execute()
}
