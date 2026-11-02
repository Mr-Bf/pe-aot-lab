static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    /* Experimental shared dispatch. The volatile load/branch is included in
     * both paths; this is not a benchmark of a deployed single-strategy build. */
    if(aot_pair_lookup_mode==0) {
        AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
        return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
    }
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
