//go:generate sh -c "go run generate_bpf.go"
package cpu

import (
	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
	"github.com/cpg1111/pprof-ebpf/pkg/srcfmt"
)

type srcTMPL struct {
	MinBlockUS       int
	MaxBlockUS       int
	TaskCommLen      int
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
	TaskCommLen      int
	StackStorageSize int
	State            int
	UOnly            bool
	KOnly            bool
	Folded           bool
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
		TaskCommLen:      opts.TaskCommLen,
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
	return mod, nil
}
