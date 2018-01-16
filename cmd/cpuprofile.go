package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cpg1111/pprof-ebpf/pkg/childprocess"
	"github.com/cpg1111/pprof-ebpf/pkg/cpu"
)

func getCPUOpts(cmd *cobra.Command) (opts cpu.RunOpts, err error) {
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
	opts.TGID, err = flags.GetInt("tgid")
	if err != nil {
		return
	}
	opts.MinBlock, err = flags.GetInt("min")
	if err != nil {
		return
	}
	opts.MaxBlock, err = flags.GetInt("max")
	if err != nil {
		return
	}
	opts.TaskCommLen, err = flags.GetInt("task-name-len")
	if err != nil {
		return
	}
	opts.StackStorageSize, err = flags.GetInt("storage-size")
	if err != nil {
		return
	}
	opts.State, err = flags.GetInt("state")
	if err != nil {
		return
	}
	opts.UOnly, err = flags.GetBool("user-space-only")
	if err != nil {
		return
	}
	opts.KOnly, err = flags.GetBool("kernel-space-only")
	if err != nil {
		return
	}
	opts.Folded, err = flags.GetBool("fold")
	if err != nil {
		return
	}
	return
}

var cpuprofileCMD = &cobra.Command{
	Use:   "cpu [OPTIONS]",
	Short: "profile cpu",
	Long: `profile cpu in user space and/or kernel space
	for a specific pid or binary`,
	Run: func(cmd *cobra.Command, args []string) {
		opts, err := getCPUOpts(cmd)
		if err != nil {
			log.WithFields(log.Fields{
				"profiler": "cpu",
			}).Fatal(err.Error())
		}
		err = cpu.Run(opts)
		if err != nil {
			log.WithFields(log.Fields{
				"profiler": "cpu",
			}).Fatal(err.Error())
		}
	},
}
