package cmd

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cpg1111/pprof-ebpf/pkg/childprocess"
	"github.com/cpg1111/pprof-ebpf/pkg/cpu"
	"github.com/cpg1111/pprof-ebpf/pkg/output"
)

func init() {
	cpuprofileCMD.Flags().String("exec", "", "command to execute and profile")
	cpuprofileCMD.Flags().Int("pid", 0, "pid to profile, if exec is provided, this is ignored")
	cpuprofileCMD.Flags().Int("tgid", 0, "specific thread group id to profile")
	cpuprofileCMD.Flags().Int("min-block", 0, "minimum blocks in a sample")
	cpuprofileCMD.Flags().Int("max-block", 1024, "maximum blocks in a sample")
	cpuprofileCMD.Flags().Int("task-name-len", 256, "max length of task names")
	cpuprofileCMD.Flags().Int("storage-size", 1024, "size of storage for stack traces")
	cpuprofileCMD.Flags().Int("state", 0, "process state to watch")
	cpuprofileCMD.Flags().Bool("user-space-only", false, "profile only user space")
	cpuprofileCMD.Flags().Bool("kernel-space-only", false, "profile only kernel space")
	cpuprofileCMD.Flags().Bool("fold", true, "whether to fold stack traces")
}

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
	opts.MinBlock, err = flags.GetInt("min-block")
	if err != nil {
		return
	}
	opts.MaxBlock, err = flags.GetInt("max-block")
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
	Use:   "cpu",
	Short: "profile cpu",
	Long: `profile cpu in user space and/or kernel space
	for a specific pid or binary`,
	Run: func(cmd *cobra.Command, args []string) {
		sigChan := make(chan os.Signal)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		opts, err := getCPUOpts(cmd)
		if err != nil {
			log.WithFields(log.Fields{
				"profiler": "cpu",
			}).Fatal(err.Error())
		}
		mod, err := cpu.Create(opts)
		if err != nil {
			log.WithFields(log.Fields{
				"profiler": "cpu",
			}).Fatal(err.Error())
		}
		parser := output.NewParser(mod)
		go parser.Parse(cpu.Format)
		defer parser.Stop()
		<-sigChan
	},
}
