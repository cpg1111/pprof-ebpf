//go:generate sh -c "go run generate_bpf.go"
package heap

import (
	"bytes"
	"fmt"
	"os"

	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
	"github.com/cpg1111/pprof-ebpf/pkg/srcfmt"
)

type srcTMPL struct {
	SizeFilter   string
	StackFlags   string
	SampleEveryN float64
	PageSize     int
}

func createProbe(mod *bpf.Module, pid int, obj, sym, fnPrefix string, canFail bool) error {
	if len(fnPrefix) == 0 {
		fnPrefix = sym
	}
	probe, err := mod.LoadUprobe(fnPrefix + "_enter")
	if err != nil {
		return err
	}
	retProbe, err := mod.LoadUprobe(fnPrefix + "_exit")
	if err != nil {
		return err
	}
	err = mod.AttachUprobe(obj, sym, probe, pid)
	if err != nil {
		if canFail {
			return nil
		}
		return fmt.Errorf("user probe error: %s", err)
	}
	err = mod.AttachUretprobe(obj, sym, retProbe, pid)
	if err != nil {
		if canFail {
			return nil
		}
		return fmt.Errorf("user return probe error: %s", err)
	}
	return nil
}

func concatSRCs(src1, src2 string) string {
	buf := &bytes.Buffer{}
	buf.WriteString(src1)
	buf.WriteString("\n")
	buf.WriteString(src2)
	return buf.String()
}

func createUserProbes(mod *bpf.Module, pid int, srcObj string) error {
	err := createProbe(mod, pid, srcObj, "malloc", "", false)
	if err != nil {
		return fmt.Errorf("failed to attach 'malloc': %s", err)
	}
	err = createProbe(mod, pid, srcObj, "calloc", "", false)
	if err != nil {
		return fmt.Errorf("failed to attach 'calloc': %s", err)
	}
	err = createProbe(mod, pid, srcObj, "realloc", "", false)
	if err != nil {
		return fmt.Errorf("failed to attach 'realloc': %s", err)
	}
	err = createProbe(mod, pid, srcObj, "posix_memalign", "", false)
	if err != nil {
		return fmt.Errorf("failed to attach 'posix_memalign': %s", err)
	}
	err = createProbe(mod, pid, srcObj, "valloc", "", false)
	if err != nil {
		return fmt.Errorf("failed to attach 'valloc': %s", err)
	}
	err = createProbe(mod, pid, srcObj, "memalign", "", false)
	if err != nil {
		return fmt.Errorf("failed to attach 'memalign': %s", err)
	}
	err = createProbe(mod, pid, srcObj, "aligned_alloc", "", true)
	if err != nil {
		return fmt.Errorf("failed to attach 'aligned_alloc': %s", err)
	}
	return nil
}

type RunOpts struct {
	PID          int
	MinSize      int
	MaxSize      int
	Count        int
	SampleRate   float64
	KTrace       bool
	CombinedOnly bool
	TraceAll     bool
	SRCObj       string
}

func Create(opts RunOpts) (*bpf.Module, error) {
	tmpl := &srcTMPL{
		StackFlags:   "BPF_F_REUSE_STACKID",
		SampleEveryN: opts.SampleRate,
		PageSize:     os.Getpagesize(),
	}
	if opts.MinSize > -1 && opts.MaxSize > -1 {
		tmpl.SizeFilter = fmt.Sprintf(
			"if ((int)(size) < %d || (int)(size) > %d) return 0;",
			opts.MinSize,
			opts.MaxSize,
		)
	} else if opts.MinSize > -1 {
		tmpl.SizeFilter = fmt.Sprintf("if ((int)(size) < %d) return 0;", opts.MinSize)
	} else if opts.MaxSize > -1 {
		tmpl.SizeFilter = fmt.Sprintf("if ((int)(size) > %d) return 0;", opts.MaxSize)
	}
	src := bpfSRC
	if opts.KTrace {
		src = concatSRCs(bpfSRC, kSRC)
	}
	if !opts.KTrace || opts.TraceAll {
		tmpl.StackFlags = tmpl.StackFlags + "|BPF_F_USER_STACK"
	}
	script, err := srcfmt.ProcessSrc(src, tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to process bpf source code: %s", err)
	}
	mod := bpf.NewModule(script.String(), nil)
	if mod == nil {
		return nil, bpferrors.ErrBadModuleBuild
	}
	if !opts.KTrace || opts.TraceAll {
		err = createUserProbes(mod, opts.PID, opts.SRCObj)
		if err != nil {
			return nil, fmt.Errorf("failed to create userspace probes: %s", err)
		}
		probe, err := mod.LoadUprobe("free_enter")
		if err != nil {
			return nil, fmt.Errorf("failed to load 'free()' probe: %s", err)
		}
		err = mod.AttachUprobe(opts.SRCObj, "free", probe, opts.PID)
		if err != nil {
			return nil, fmt.Errorf("failed to attach 'free()' probe: %s", err)
		}
	} else {
		fmt.Println("attaching kernel tracepoints...")
	}
	return mod, nil
}
