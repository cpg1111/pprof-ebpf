//go:generate sh -c "go run generate_bpf.go"
package cpu

import (
	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/cpuonline"

	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
	"github.com/cpg1111/pprof-ebpf/pkg/bpftypes"
	"github.com/cpg1111/pprof-ebpf/pkg/srcfmt"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

type srcTMPL struct {
	MinBlockUS       int
	MaxBlockUS       int
	StackStorageSize int
	ThreadFilter     string
	StateFilter      string
	UserStackGet     string
	KernelStackGet   string
}

type procKey struct {
	Pid           uint32
	TGid          uint32
	UserStackID   int
	KernelStackID int
	Name          []byte
}

type RunOpts struct {
	PID              int
	TGID             int
	MinBlock         int
	MaxBlock         int
	StackStorageSize int
	UOnly            bool
	KOnly            bool
	Folded           bool
	SamplePeriod     uint64
	SampleFrequency  uint64
}

func attachPerfEvent(mod *bpf.Module, fnName string, evType, evConfig uint32, samplePeriod, sampleFreq uint64, pid, cpu, groupFD int) (int, error) {
	fd, err := mod.Load(fnName, C.BPF_PROG_TYPE_PERF_EVENT, 0, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to load BPF perf event %v : %v", fnName, err)
	}
	res, err := C.bpf_attach_perf_event(
		C.int(fd),
		C.uint32_t(evType),
		C.uint32_t(evConfig),
		C.uint64_t(samplePeriod),
		C.uint64_t(sampleFreq),
		C.pid_t(pid),
		C.int(cpu),
		C.int(groupFD),
	)
	if res < 0 || err != nil {
		return -1, fmt.Errorf("failed to attach BPF perf event %v : %v", fnName, err)
	}
	return int(res), nil
}

func attachPerfEventCPUs(mod *bpf.Module, fnName string, evType, evConfig uint32, samplePeriod, sampleFreq uint64, pid, cpu, groupFD int) error {
	if cpu >= 0 {
		_, err := attachPerfEvent(
			mod,
			fnName,
			evType,
			evConfig,
			samplePeriod,
			sampleFreq,
			pid,
			cpu,
			groupFD,
		)
		if err != nil {
			return err
		}
		return nil
	}
	cpus, err := cpuonline.Get()
	if err != nil {
		return err
	}
	for _, c := range cpus {
		_, err = attachPerfEvent(
			mod,
			fnName,
			evType,
			evConfig,
			samplePeriod,
			sampleFreq,
			pid,
			int(c),
			groupFD,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func Create(opts RunOpts) (*bpf.Module, error) {
	var threadFilter, uStackGet, kStackGet string
	if opts.TGID != 0 {
		threadFilter = fmt.Sprintf("tgid == %d", opts.TGID)
	} else if opts.PID != 0 {
		threadFilter = fmt.Sprintf("pid == %d", opts.PID)
	} else if opts.UOnly {
		threadFilter = "!(prev->flags & PF_KTHREAD)"
		kStackGet = "-1"
	} else if opts.KOnly {
		threadFilter = "prev->flags & PF_KTHREAD"
		uStackGet = "-1"
	} else {
		threadFilter = "1"
	}
	if len(uStackGet) == 0 {
		uStackGet = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)"
	}
	if len(kStackGet) == 0 {
		kStackGet = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
	}
	tmpl := &srcTMPL{
		ThreadFilter:     threadFilter,
		UserStackGet:     uStackGet,
		KernelStackGet:   kStackGet,
		StackStorageSize: opts.StackStorageSize,
	}
	script, err := srcfmt.ProcessSrc(bpfSRC, tmpl)
	if err != nil {
		return nil, err
	}
	mod := bpf.NewModule(script.String(), nil)
	if mod == nil {
		return nil, bpferrors.ErrBadModuleBuild
	}
	attachPerfEventCPUs(
		mod,
		"do_perf_event",
		bpftypes.PerfTypeSoftware,
		bpftypes.PerfSWConfigCPUClock,
		opts.SamplePeriod,
		opts.SampleFrequency,
		opts.PID,
		-1,
		-1,
	)
	return mod, nil
}
