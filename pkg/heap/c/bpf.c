#include <uapi/linux/ptrace.h>

struct alloc_info_t {
    u64 size;
    u64 timestamp_ns;
    int stack_id;
};

struct combined_alloc_info_t {
    u64 total_size;
    u64 number_of_allocs;
};

BPF_HASH(sizes, u64);
BPF_TABLE("hash", u64, struct alloc_info_t, allocs, 1000000);
BPF_HASH(memptrs, u64, u64);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_TABLE("hash", u64, struct combined_alloc_info_t, combined_allocs, 10240);

static inline void update_statistics_add(u64 stack_id, u64 sz) {
    struct combined_alloc_info_t *existing_cinfo;
    struct combined_alloc_info_t cinfo = {0};
    existing_cinfo = combined_allocs.lookup(&stack_id);
    if (existing_cinfo != 0)
        cinfo = *existing_cinfo;
    cinfo.total_size += sz;
    cinfo.number_of_allocs += 1;
    combined_allocs.update(&stack_id, &cinfo);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
    struct combined_alloc_info_t *existing_cinfo;
    struct combined_alloc_info_t cinfo = {0};
    existing_cinfo = combined_allocs.lookup(&stack_id);
    if (existing_cinfo != 0)
        cinfo = *existing_cinfo;
    if (sz >= cinfo.total_size) {
        cinfo.total_size = 0;
    } else {
        cinfo.total_size -= sz;
    }
    if (cinfo.number_of_allocs > 0)
        cinfo.number_of_allocs -= 1;
    combined_allocs.update(&stack_id, &cinfo);
}

static inline int gen_alloc_enter(struct pt_regs *ctx, size_t size) {
    {{ .SizeFilter }}
    if ({{ .SampleEveryN }} > 0) {
        u64 ts = bpf_ktime_get_ns();
        if ((int)(ts) % {{ .SampleEveryN }} != 0) {
            ts = (u64)((int)(ts) - ((int)(ts) % {{.SampleEveryN}}));
        }
    }
    u64 pid = bpf_get_current_pid_tgid();
    u64 size64 = size;
    sizes.update(&pid, &size64);
    bpf_trace_printk("alloc entered, size = %u\\n", size);
    return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
    u64 pid = bpf_get_current_pid_tgid();
    u64* size64 = sizes.lookup(&pid);
    struct alloc_info_t info = {0};
    if (size64 == 0)
        return 0;
    info.size = *size64;
    sizes.delete(&pid);
    info.timestamp_ns = bpf_ktime_get_ns();
    info.stack_id = stack_traces.get_stackid(ctx, {{ .StackFlags }});
    allocs.update(&address, &info);
    update_statistics_add(info.stack_id, info.size);
    bpf_trace_printk("alloc exited, size = %lu, result = %lx\\n", info.size, address);
    return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
    u64 addr = (u64)(address);
    struct alloc_info_t *info = allocs.lookup(&addr);
    if (info == 0)
        return 0;
    allocs.delete(&addr);
    update_statistics_del(info->stack_id, info->size);
    bpf_trace_printk("free entered, address = %lx, size = %lu\\n", address, info->size);
    return 0;
}

int malloc_enter(struct pt_regs *ctx, size_t size) {
    return gen_alloc_enter(ctx, size);
}

int malloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

int free_enter(struct pt_regs *ctx, void *address) {
    return gen_free_enter(ctx, address);
}

int calloc_enter(struct pt_regs *ctx, size_t nmemb, size_t size) {
    return gen_alloc_enter(ctx, nmemb * size);
}

int calloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

int realloc_enter(struct pt_regs *ctx, void *ptr, size_t size) {
    gen_free_enter(ctx, ptr);
    return gen_alloc_enter(ctx, size);
}

int realloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

int posix_memalign_enter(struct pt_regs *ctx, void **memptr, size_t alignment, size_t size) {
    u64 memptr64 = (u64)(size_t)(memptr);
    u64 pid = bpf_get_current_pid_tgid();
    memptrs.update(&pid, &memptr64);
    return gen_alloc_enter(ctx, size);
}

int posix_memalign_exit(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *memptr64 = memptrs.lookup(&pid);
    void *addr;
    if (memptr64 == 0)
        return 0;
    memptrs.delete(&pid);
    if (bpf_probe_read(&addr, sizeof(void*), (void*)(size_t)(*memptr64)))
        return 0;
    u64 addr64 = (u64)(size_t)(addr);
    return gen_alloc_exit2(ctx, addr64);
}

int aligned_alloc_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
    return gen_alloc_enter(ctx, size);
}

int aligned_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

int valloc_enter(struct pt_regs *ctx, size_t size) {
    return gen_alloc_enter(ctx, size);
}

int valloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

int memalign_enter(struct pt_regs *ctx, size_t alignment, size_t size) {
    return gen_alloc_enter(ctx, size);
}

int memalign_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

int pvalloc_enter(struct pt_regs *ctx, size_t size) {
    return gen_alloc_enter(ctx, size);
}

int pvalloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}
