package cpu

import (
	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const (
	bpfSRC = `
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
	u64 kernel_ip;
	u64 kernel_ret_ip;
	int kernel_stack_id;
	char name[{{.TaskNameLen}}];
} task_t;

BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, {{.StackStoreSize}});

int do_perf_event(struct bpf_perf_event_data *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!({{.ThreadFilter}})) // TODO get num threads
		return 0;
	// create map key
	u64 zero = 0, *val;
	struct task_t task = {.pid = pid};
	bpf_get_current_comm(&task.name, sizeof(task.name));
	// get stacks
	key.user_stack_id = stack_traces.get_stackid(&ctx->regs, 0 | BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
	key.kernel_stack_id = stack_traces.get_stackid(&ctx->regs, 0 | BPF_F_REUSE_STACKID);
	if (key.kernel_stack_id >= 0) {
		// populate extras to fix the kernel stack
		struct pt_regs regs = {};
		bpf_probe_read(&regs, sizeof(regs), (void *)&ctx->regs);
		u64 ip = PT_REGS_IP(&regs);
		// if ip isn't sane, leave key ips as zero for later checking
#ifdef CONFIG_RANDOMIZE_MEMORY
		if (ip > __PAGE_OFFSET_BASE) {
#else
		if (ip > PAGE_OFFSET) {
#endif
            key.kernel_ip = ip;				        
		}
	}
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;									}
}
`
)

type srcTMPL struct {
	TaskNameLen    int
	StackStoreSize int
	ThreadFilter   string
}

type task struct {
	Pid  uint32
	Uid  uint32
	Gid  uint32
	Name []byte
}

func Run() {
	// TODO template src bpf
	mod := bpf.NewModule(bpfSRC)
	defer mod.Close()

}
