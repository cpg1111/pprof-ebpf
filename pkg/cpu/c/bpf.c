#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    u64 kernel_ip;
    u64 kernel_ret_ip;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE(stack_traces, {{ .StackStorageSize }});

int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!({{ .ThreadFilter }}))
        return 0;

    u64 zero = 0, *val;
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.name, sizeof(key.name));
    
    key.user_stack_id = {{ .UserStackGet }};
    key.kernel_stack_id = {{ .KernelStackGet }};
    if (key.kernel_stack_id >= 0) {
        // populate extras to fix the kernel stack
        struct pt_regs regs = {};
        bpf_probe_read(&regs, sizeof(regs), (void *)&ctx->regs);
        u64 ip = PT_REGS_IP(&regs);
        u64 page_offset;
        // if ip isn't sane, leave key ips as zero for later checking
        #if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
        #elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
        #if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
        #else
        page_offset = __PAGE_OFFSET_BASE_L4;
        #endif
        #else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
        #endif
        if (ip > page_offset) {
            key.kernel_ip = ip;
        }
    }
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
}
