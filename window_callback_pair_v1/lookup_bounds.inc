/* Untimed lookup-only boundary comparisons against an independent linear
 * oracle. Caller supplies need(), instruction(), and the complete Context. */
typedef struct { uint64_t queries,hits,misses,contexts; } LookupChecks;
static void lookup_one(AotContext *ctx,uint64_t pc,LookupChecks *counts) {
    const AotInstruction *want=NULL;
    if(pc>=ctx->module_base && pc-ctx->module_base<=UINT32_MAX) {
        for(size_t i=0;i<ctx->instruction_count;i++)
            if(ctx->instructions[i].rva==pc-ctx->module_base){want=ctx->instructions+i;break;}
    }
    for(unsigned mode=0;mode<2;mode++) {
        aot_pair_lookup_mode=mode;
        need(instruction(ctx,pc)==want,"lookup pointer differs from linear oracle");
    }
    counts->queries++;if(want)counts->hits++;else counts->misses++;
}
static void lookup_context(AotContext *ctx,LookupChecks *counts) {
    AotContext before;memcpy(&before,ctx,sizeof before);
    size_t bytes=ctx->instruction_count*sizeof *ctx->instructions;
    AotInstruction *copy=malloc(bytes);need(copy!=NULL,"lookup reference allocation");
    memcpy(copy,ctx->instructions,bytes);counts->contexts++;
    lookup_one(ctx,0,counts);lookup_one(ctx,UINT64_MAX,counts);
    lookup_one(ctx,ctx->module_base,counts);
    if(ctx->module_base)lookup_one(ctx,ctx->module_base-1,counts);
    if(ctx->module_base<=UINT64_MAX-UINT32_MAX)
        lookup_one(ctx,ctx->module_base+UINT32_MAX,counts);
    if(ctx->module_base<UINT64_MAX-UINT32_MAX)
        lookup_one(ctx,ctx->module_base+UINT64_C(0x100000000),counts);
    for(size_t i=0;i<ctx->instruction_count;i++) {
        uint64_t pc=ctx->module_base+ctx->instructions[i].rva;
        if(pc)lookup_one(ctx,pc-1,counts);
        /* Exact start, every interior byte, and the first byte past the end. */
        for(unsigned offset=0;offset<=ctx->instructions[i].length;offset++)
            lookup_one(ctx,pc+offset,counts);
    }
    uint32_t random=UINT32_C(0x91e10da5);
    for(unsigned i=0;i<2048;i++) {
        random^=random<<13;random^=random>>17;random^=random<<5;
        if(ctx->module_base<=UINT64_MAX-random)lookup_one(ctx,ctx->module_base+random,counts);
    }
    need(!memcmp(&before,ctx,sizeof before) && !memcmp(copy,ctx->instructions,bytes),
         "lookup mutated context or instructions");
    free(copy);
}
static LookupChecks lookup_boundaries(AotContext *actual) {
    LookupChecks counts={0};lookup_context(actual,&counts);
    const uint64_t bases[]={0,UINT64_C(0x140000000),UINT64_C(0x180000000),UINT64_MAX-UINT32_MAX};
    const size_t sizes[]={1,2,3,7,8,9,31,32,33,127,256,1024};
    AotInstruction source[1024];
    for(size_t b=0;b<sizeof bases/sizeof *bases;b++) {
        for(size_t n=0;n<sizeof sizes/sizeof *sizes;n++) {
            size_t count=sizes[n];
            /* Reversed input also exercises the actual context's sort/validation. */
            for(size_t i=0;i<count;i++) {
                size_t index=count-i-1;
                source[i]=(AotInstruction){(uint32_t)(7+index*17),(uint32_t)(index%15+1),0,0,0};
            }
            AotContext *ctx=aot_context_create(bases[b],source,count,1,0,0);
            need(ctx!=NULL,"valid synthetic lookup context rejected");
            lookup_context(ctx,&counts);aot_context_destroy(ctx);
        }
        const AotInstruction extremes[]={
            {UINT32_C(0xfffffffe),1,0,0,0},{UINT32_C(0x7fffffff),1,0,0,0},
            {UINT32_C(0xfffffff0),14,0,0,0},{0,1,0,0,0},{2,1,0,0,0}
        };
        AotContext *ctx=aot_context_create(bases[b],extremes,sizeof extremes/sizeof *extremes,1,0,0);
        need(ctx!=NULL,"extreme lookup context rejected");
        lookup_context(ctx,&counts);aot_context_destroy(ctx);
    }
    aot_pair_lookup_mode=0;return counts;
}
