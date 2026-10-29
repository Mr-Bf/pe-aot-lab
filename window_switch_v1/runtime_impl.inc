/* Included after instruction() in the window transaction implementation.
 * Reuses its private Context, byte-wise mappings and first-fault contract.
 * Code intentionally adds no replacement for the existing API/COM engine. */
#ifndef AOT_WINDOW_SWITCH_V1
#error Window switch implementation requires its versioned build contract
#endif

uint32_t aot_configure_switch(AotContext *ctx,uint64_t pc,const uint64_t *targets,size_t count) {
    if(!ctx || ctx->result.steps || ctx->in_instruction || ctx->result.fault.status ||
       ctx->switch_binding_attempted || ctx->switch_count || !targets || count<2 ||
       count>AOT_WINDOW_SWITCH_MAX_TARGETS)return AOT_INVALID;
    const AotInstruction *jump=instruction(ctx,pc);
    if(!jump || jump->kind!=AOT_SWITCH_JUMP || jump->target_rva)return AOT_INVALID;
    size_t jumps=0;
    for(size_t i=0;i<ctx->instruction_count;i++)jumps+=ctx->instructions[i].kind==AOT_SWITCH_JUMP;
    if(jumps!=1)return AOT_INVALID;
    for(size_t i=0;i<count;i++)if(!instruction(ctx,targets[i]))return AOT_INVALID;
    ctx->switch_pc=pc;ctx->switch_count=count;
    memcpy(ctx->switch_targets,targets,count*sizeof(uint64_t));
    return AOT_OK;
}

static uint32_t aot_window_switch_bind_failure(AotContext *ctx,uint32_t status,
                                              uint64_t table,size_t size) {
    fault(ctx,status,table,size,GM_READ);
    return status;
}

uint32_t aot_bind_switch(AotContext *ctx,uint64_t table,const uint8_t *expected,size_t size) {
    if(!ctx)return AOT_INVALID;
    if(ctx->switch_binding_attempted || ctx->result.steps || ctx->in_instruction || ctx->result.fault.status) {
        ctx->switch_binding_attempted=1;ctx->switch_bound=0;
        fault(ctx,AOT_INVALID,table,size,GM_READ);
        return AOT_INVALID;
    }
    ctx->switch_binding_attempted=1;
    if(!expected || !ctx->switch_count || size!=ctx->switch_count*4 ||
       size>AOT_WINDOW_SWITCH_MAX_TARGETS*4 || table%4 || table>UINT64_MAX-(size-1))
        return aot_window_switch_bind_failure(ctx,AOT_INVALID,table,size);
    const uint8_t *bytes[AOT_WINDOW_SWITCH_MAX_TARGETS*4];
    uint8_t rights[AOT_WINDOW_SWITCH_MAX_TARGETS*4];
    /* Resolve the whole range first, matching the window memory model's
     * unmapped-before-protection precedence. No spanning host pointer forms. */
    for(size_t i=0;i<size;i++) {
        const GuestMemory *found=NULL;uint64_t address=table+i;
        for(size_t j=0;j<ctx->region_count;j++) {
            const GuestMemory *region=&ctx->regions[j];
            if(address>=region->base && address-region->base<region->size){found=region;break;}
        }
        if(!found)return aot_window_switch_bind_failure(ctx,AOT_BOUNDS,table,size);
        size_t offset=(size_t)(address-found->base);
        bytes[i]=found->bytes+offset;rights[i]=found->permissions[offset/GM_PAGE];
    }
    for(size_t i=0;i<size;i++)if(rights[i]!=GM_READ)
        return aot_window_switch_bind_failure(ctx,AOT_PROTECTION,table,size);
    for(size_t i=0;i<size;i++)if(*bytes[i]!=expected[i])
        return aot_window_switch_bind_failure(ctx,AOT_BAD_INSTRUCTION,table,size);
    for(size_t i=0;i<ctx->switch_count;i++) {
        const uint8_t *p=expected+i*4;
        uint32_t raw=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
        int64_t displacement=raw<0x80000000u?(int64_t)raw:(int64_t)raw-INT64_C(0x100000000);
        uint64_t target;
        if(displacement>=0) {
            if(table>UINT64_MAX-(uint64_t)displacement)
                return aot_window_switch_bind_failure(ctx,AOT_INVALID,table,size);
            target=table+(uint64_t)displacement;
        } else {
            uint64_t magnitude=(uint64_t)(-(displacement+1))+1;
            if(table<magnitude)return aot_window_switch_bind_failure(ctx,AOT_INVALID,table,size);
            target=table-magnitude;
        }
        if(target!=ctx->switch_targets[i])
            return aot_window_switch_bind_failure(ctx,AOT_BAD_INSTRUCTION,table,size);
    }
    ctx->switch_bound=1;
    return AOT_OK;
}

/* Hook before the existing RET validation and common rollback branch. */
static void aot_window_switch_validate_commit(AotState *state,AotContext *ctx,uint64_t next_pc) {
    if(ctx->result.fault.status || ctx->current->kind!=AOT_SWITCH_JUMP)return;
    bool matched=false;
    if(ctx->switch_bound && ctx->current_pc==ctx->switch_pc && !ctx->pending_size &&
       aot_get_register(state,AOT_RSP)==aot_get_register(&ctx->snapshot,AOT_RSP))
        for(size_t i=0;i<ctx->switch_count;i++)if(next_pc==ctx->switch_targets[i])matched=true;
    if(!matched)fault(ctx,AOT_BAD_INSTRUCTION,next_pc,0,AOT_EXEC);
}

/* Hook only after the common rollback branch, committed memory writes and
 * CALL/RET depth bookkeeping, immediately before the successful RIP update. */
static void aot_window_switch_commit_complete(AotContext *ctx) {
    if(ctx->current->kind==AOT_SWITCH_JUMP)ctx->switch_commits++;
}

uint64_t aot_window_switch_commits(const AotContext *ctx) {
    return ctx?ctx->switch_commits:0;
}

void *aot_switch_miss(void *state,uint64_t pc,void *opaque) {
    AotContext *ctx=(AotContext*)opaque;
    if(ctx) {
        fault(ctx,AOT_BAD_INSTRUCTION,pc,0,AOT_EXEC);
        if(ctx->in_instruction) {
            memcpy(state,&ctx->snapshot,sizeof(AotState));
            ctx->in_instruction=0;ctx->pending_size=0;
            ctx->d3d_binding_valid=0;ctx->import_binding_valid=0;
        }
    }
    return opaque;
}
