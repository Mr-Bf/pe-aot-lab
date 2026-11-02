static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    const uint32_t rva=(uint32_t)(pc-ctx->module_base);
    size_t low=0,high=ctx->instruction_count;
    while(low<high) {
        size_t middle=low+(high-low)/2;
        const AotInstruction *found=ctx->instructions+middle;
        if(found->rva==rva)return found;
        if(found->rva<rva)low=middle+1;
        else high=middle;
    }
    return NULL;
}
