/* Included only inside the versioned window transaction AotContext. */
uint64_t switch_pc,switch_targets[AOT_WINDOW_SWITCH_MAX_TARGETS];
size_t switch_count;
uint32_t switch_bound,switch_binding_attempted;
uint64_t switch_commits;
