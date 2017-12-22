package cpu

import (
	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
	"github.com/cpg1111/pprof-ebpf/pkg/srcfmt"
)

import "C"

const (
	bpfSRC = `
	#include <uapi/linux/ptrace.h>
	#include <linux/sched.h>
	
	#define MINBLOCK_US {{ .MinBlockUS }}
	#define MAXBLCOK_US {{ .MaxBlockUS }}

	struct proc_key_t {
		u32 pid;
		u32 tgid;
		int user_stack_id;
		int kernel_stack_id;
		char name[{{ .TaskCommLen }}];
	};

	BPF_HASH(counts, struct proc_key_t);
	BPF_HASH(start, u32);
	BPF_STACK_TRACE(stack_traces, {{ .StackStorageSize }});

	int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
		u32 pid = prev->pid;
		u32 tgid = prev->tgid;
		u64 ts, *tsp;
		// record previous thread sleep time
		if (({{ .ThreadFilter }}) && ({{ .StateFilter }})) {
			ts = bpf_ktime_get_ns();
			start.update(&pid, &ts);								    
		}

		// get the current thread's start time
		pid = bpf_get_current_pid_tgid();
		tgid = bpf_get_current_pid_tgid() >> 32;
		tsp = start.lookup(&pid);
		if (tsp == 0) {
			return 0;        // missed start or filtered					    
		}

		// calculate current thread's delta time
		u64 delta = bpf_ktime_get_ns() - *tsp;
		start.delete(&pid);
		delta = delta / 1000;
		if ((delta < {{ .MinBlockUS }}) || (delta > {{ .MaxBlockUS }})) {
			return 0;					    
		}

		// create map key
		u64 zero = 0, *val;
		struct proc_key_t key = {};

		key.pid = pid;
		key.tgid = tgid;
		key.user_stack_id = {{ .UserStackGet }};
		key.kernel_stack_id = {{ .KernelStackGet }};
		bpf_get_current_comm(&key.name, sizeof(key.name));

		val = counts.lookup_or_init(&key, &zero);
		(*val) += delta;
		return 0;
	}
`
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

func Run(pid, tgid, minBlock, maxBlock, taskCommLen, stackStorageSize, state int, uOnly, kOnly, folded bool) (err error) {
	var threadCtx, stackCtx, threadFilter, stateFilter, uStackGet, kStackGet string
	if tgid != 0 {
		threadCtx = fmt.Sprintf("PID %d", tgid)
		threadFilter = fmt.Sprintf("tgid == %d", tgid)
	} else if pid != 0 {
		threadCtx = fmt.Sprintf("PID %d", pid)
		threadFilter = fmt.Sprintf("pid == %d", pid)
	} else if uOnly {
		threadCtx = "user threads"
		threadFilter = "!(prev->flags & PF_KTHREAD)"
		kStackGet = "-1"
	} else if kOnly {
		threadCtx = "kernel threads"
		threadFilter = "prev->flags & PF_KTHREAD"
		uStackGet = "-1"
	} else {
		threadCtx = "all threads"
		threadFilter = "1"
	}
	if state == 0 {
		stateFilter = "prev->state == 0"
	} else if state <= -1 {
		stateFilter = fmt.Sprintf("prev->state & %d", state)
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
		MinBlockUS:       minBlock,
		MaxBlockUS:       maxBlock,
		TaskCommLen:      taskCommLen,
		StackStorageSize: stackStorageSize,
		ThreadFilter:     threadFilter,
		StateFilter:      stateFilter,
		UserStackGet:     uStackGet,
		KernelStackGet:   kStackGet,
	}
	script, err := srcfmt.ProcessSrc(bpfSRC, tmpl)
	if err != nil {
		return err
	}
	mod := bpf.NewModule(script.String(), nil)
	if mod == nil {
		return bpferrors.ErrBadModuleBuild
	}
	defer mod.Close()
	ev, err := mod.LoadKprobe("oncpu")
	err = mod.AttachKprobe("finish_task_switch", ev)
	if err != nil {
		return err
	}
	if !folded {
		fmt.Printf("Tracing on-cpu (us) of %s by %s stack\n", threadCtx, stackCtx)
	}
	iter := mod.TableIter()
	for res := range iter { // TODO use this data
		fmt.Printf("%+v\n", res)
	}
	return nil
}
