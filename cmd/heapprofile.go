package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cpg1111/pprof-ebpf/pkg/childprocess"
	"github.com/cpg1111/pprof-ebpf/pkg/heap"
)

func getHeapOpts(cmd *cobra.Command) (opts heap.RunOpts, err error) {
	flags := cmd.Flags()
	exec, err := flags.GetString("exec")
	if err != nil {
		return
	}
	if len(exec) > 0 {
		opts.PID, err = childprocess.Exec(exec)
		if err != nil {
			return
		}
	} else {
		opts.PID, err = flags.GetInt("pid")
		if err != nil {
			return
		}
	}
	opts.MinSize, err = flags.GetInt("min-size")
	if err != nil {
		return
	}
	opts.MaxSize, err = flags.GetInt("max-size")
	if err != nil {
		return
	}
	opts.SampleRate, err = flags.GetInt("count")
	if err != nil {
		return
	}
	opts.KTrace, err = flags.GetBool("ktrace")
	if err != nil {
		return
	}
	opts.TraceAll, err = flags.GetBool("all")
	if err != nil {
		return
	}
	opts.SRCObj, err = flags.GetString("src")
	if err != nil {
		return
	}
	return
}

var heapprofileCMD = &cobra.Command{
	Use:   "heap [OPTIONS]",
	Short: "profile heap allocations",
	Long: `profile heap allocations in user space and/or kernel space
	for a specific pid or binary`,
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := getHeapOpts(cmd)
		if err != nil {
			log.WithFields(log.Fields{
				"profiler": "heap",
			}).Fatal(err.Error())
		}
		err = heap.Run(opts)
		if err != nil {
			log.WithFields(log.Fields{
				"profiler": "heap",
			}).Fatal(err.Error())
		}
	},
}
