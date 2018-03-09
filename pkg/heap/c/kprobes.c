TRACEPOINT_PROBE(kmem, kmalloc) {
    gen_alloc_enter((struct pt_regs *)(args), args->bytes_alloc);
    return gen_alloc_exit2((struct pt_regs *)(args), (size_t)(args->ptr));
}

TRACEPOINT_PROBE(kmem, kmalloc_node) {
    gen_alloc_enter((struct pt_regs *)(args), args->bytes_alloc);
    return gen_alloc_exit2((struct pt_regs *)(args), (size_t)(args->ptr));
}

TRACEPOINT_PROBE(kmem, kfree) {
    return gen_free_enter((struct pt_regs *)(args), (void *)(args->ptr));
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc) {
    gen_alloc_enter((struct pt_regs *)(args), args->bytes_alloc);
    return gen_alloc_exit2((struct pt_regs *)(args), (size_t)(args->ptr));
}

TRACEPOINT_PROBE(kmem, kmem_cache_alloc_node) {
    gen_alloc_enter((struct pt_regs *)(args), args->bytes_alloc);
    return gen_alloc_exit2((struct pt_regs *)(args), (size_t)(args->ptr));
}

TRACEPOINT_PROBE(kmem, kmem_cache_free) {
    return gen_free_enter((struct pt_regs *)(args), (void *)(args->ptr));
}

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
    gen_alloc_enter((struct pt_regs *)(args), {{ .PageSize }} << args->order);
    return gen_alloc_exit2((struct pt_regs *)(args), args->pfn);
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
    return gen_free_enter((struct pt_regs *)(args), (void *)(args->pfn));
}
