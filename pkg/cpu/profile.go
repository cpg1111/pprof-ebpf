//go:generate sh -c "go run generate_bpf.go"
package cpu

import (
	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
	"github.com/cpg1111/pprof-ebpf/pkg/srcfmt"
)

import "C"

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

/*func Create(opts RunOpts) (*bpf.Module, error) {
	var threadCtx, stackCtx, threadFilter, stateFilter, uStackGet, kStackGet string
	if opts.TGID != 0 {
		threadCtx = fmt.Sprintf("PID %d", opts.TGID)
		threadFilter = fmt.Sprintf("tgid == %d", opts.TGID)
	} else if opts.PID != 0 {
		threadCtx = fmt.Sprintf("PID %d", opts.PID)
		threadFilter = fmt.Sprintf("pid == %d", opts.PID)
	} else if opts.UOnly {
		threadCtx = "user threads"
		threadFilter = "!(prev->flags & PF_KTHREAD)"
		kStackGet = "-1"
	} else if opts.KOnly {
		threadCtx = "kernel threads"
		threadFilter = "prev->flags & PF_KTHREAD"
		uStackGet = "-1"
	} else {
		threadCtx = "all threads"
		threadFilter = "1"
	}
	if opts.State == 0 {
		stateFilter = "prev->state == 0"
	} else if opts.State <= -1 {
		stateFilter = fmt.Sprintf("prev->state & %d", opts.State)
	} else {
		stateFilter = "1"
	}
	if len(uStackGet) == 0 {
		uStackGet = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)"
	}
	if len(kStackGet) == 0 {
		kStackGet = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
	}
	tmpl := &srcTMPL{
		MinBlockUS:       opts.MinBlock,
		MaxBlockUS:       opts.MaxBlock,
		TaskCommLen:      opts.TaskCommLen,
		StackStorageSize: opts.StackStorageSize,
		ThreadFilter:     threadFilter,
		StateFilter:      stateFilter,
		UserStackGet:     uStackGet,
		KernelStackGet:   kStackGet,
	}
	script, err := srcfmt.ProcessSrc(bpfSRC, tmpl)
	if err != nil {
		return nil, err
	}
	mod := bpf.NewModule(script.String(), nil)
	if mod == nil {
		return nil, bpferrors.ErrBadModuleBuild
	}
	ev, err := mod.LoadKprobe("oncpu")
	if err != nil {
		return nil, err
	}
	err = mod.AttachKprobe("finish_task_switch", ev)
	if err != nil {
		return nil, err
	}
	if !opts.Folded {
		fmt.Printf("Tracing on-cpu (us) of %s by %s stack\n", threadCtx, stackCtx)
	}
	return mod, nil
}*/

func Create(opts RunOpts) (*bpf.Module, error) {
	var /*threadCtx, */ threadFilter, uStackGet, kStackGet string
	if opts.TGID != 0 {
		//		threadCtx = fmt.Sprintf("PID %d", opts.TGID)
		threadFilter = fmt.Sprintf("tgid == %d", opts.TGID)
	} else if opts.PID != 0 {
		//		threadCtx = fmt.Sprintf("PID %d", opts.PID)
		threadFilter = fmt.Sprintf("pid == %d", opts.PID)
	} else if opts.UOnly {
		//		threadCtx = "user threads"
		threadFilter = "!(prev->flags & PF_KTHREAD)"
		kStackGet = "-1"
	} else if opts.KOnly {
		//		threadCtx = "kernel threads"
		threadFilter = "prev->flags & PF_KTHREAD"
		uStackGet = "-1"
	} else {
		//		threadCtx = "all threads"
		threadFilter = "1"
	}
	if len(uStackGet) == 0 {
		uStackGet = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)"
	}
	if len(kStackGet) == 0 {
		kStackGet = "stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK)"
	}
	tmpl := &srcTMPL{
		TaskCommLen:    opts.TaskCommLen,
		ThreadFilter:   threadFilter,
		UserStackGet:   uStackGet,
		KernelStackGet: kStackGet,
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
