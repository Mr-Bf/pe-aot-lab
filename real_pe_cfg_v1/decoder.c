/* Read-only instruction metadata bridge. This never executes decoded bytes. */
#include <xed/xed-interface.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

struct writer { char *out; size_t capacity, used; int failed; };
static void append(struct writer *w, const char *format, ...) {
  if (w->failed) return;
  va_list args; va_start(args, format);
  int n = vsnprintf(w->out + w->used, w->capacity - w->used, format, args);
  va_end(args);
  if (n < 0 || (size_t)n >= w->capacity - w->used) w->failed = 1;
  else w->used += (size_t)n;
}

void pe_cfg_xed_init(void) { xed_tables_init(); }

/* All strings emitted here are XED enum names, not input-derived text. */
int pe_cfg_xed_decode(const uint8_t *bytes, size_t count, char *out, size_t capacity) {
  if (!bytes || !out || !capacity || count < 1 || count > 15) return -1;
  struct writer w = {out, capacity, 0, 0};
  xed_state_t mode; xed_state_zero(&mode);
  mode.mmode = XED_MACHINE_MODE_LONG_64;
  mode.stack_addr_width = XED_ADDRESS_WIDTH_64b;
  xed_decoded_inst_t d; xed_decoded_inst_zero_set_mode(&d, &mode);
  /* Enable recognition of all compiled ISA forms, including otherwise inert
     CET/MPX/LZCNT/TZCNT/PAUSE aliases. This is not host CPUID or guest support. */
  xed_decoded_inst_set_input_chip(&d, XED_CHIP_ALL);
  xed_error_enum_t error = xed_decode(&d, bytes, (unsigned int)count);
  if (error != XED_ERROR_NONE) {
    append(&w, "{\"status\":\"invalid\",\"error\":\"%s\"}", xed_error_enum_t2str(error));
    return w.failed ? -1 : (int)w.used;
  }
  const xed_operand_values_t *values = xed_decoded_inst_operands_const(&d);
  append(&w, "{\"status\":\"decoded\",\"length\":%u,\"iclass\":\"%s\","
    "\"category\":\"%s\",\"extension\":\"%s\",\"isa_set\":\"%s\","
    "\"address_width\":%u,\"operand_width\":%u,\"branch_displacement\":%lld,"
    "\"branch_displacement_width\":%u,\"ring0\":%s,\"far_transfer\":%s,",
    xed_decoded_inst_get_length(&d),
    xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&d)),
    xed_category_enum_t2str(xed_decoded_inst_get_category(&d)),
    xed_extension_enum_t2str(xed_decoded_inst_get_extension(&d)),
    xed_isa_set_enum_t2str(xed_decoded_inst_get_isa_set(&d)),
    xed_operand_values_get_effective_address_width(values),
    xed_decoded_inst_get_operand_width(&d),
    (long long)xed_decoded_inst_get_branch_displacement(&d),
    xed_decoded_inst_get_branch_displacement_width_bits(&d),
    xed_decoded_inst_get_attribute(&d, XED_ATTRIBUTE_RING0) ? "true" : "false",
    xed_decoded_inst_get_attribute(&d, XED_ATTRIBUTE_FAR_XFER) ? "true" : "false");
  append(&w, "\"prefixes\":{\"legacy_count\":%u,\"lock\":%s,\"rep\":%s,"
    "\"repne\":%s,\"address_size\":%s,\"operand_size\":%s,\"rex_w\":%s,"
    "\"xacquire\":%s,\"xrelease\":%s},\"memory_operands\":[",
    xed_decoded_inst_get_nprefixes(&d),
    xed_operand_values_has_lock_prefix(values) ? "true" : "false",
    xed_operand_values_has_rep_prefix(values) ? "true" : "false",
    xed_operand_values_has_repne_prefix(values) ? "true" : "false",
    xed_operand_values_has_address_size_prefix(values) ? "true" : "false",
    xed_operand_values_has_operand_size_prefix(values) ? "true" : "false",
    xed_operand_values_has_rexw_prefix(values) ? "true" : "false",
    xed_decoded_inst_is_xacquire(&d) ? "true" : "false",
    xed_decoded_inst_is_xrelease(&d) ? "true" : "false");
  unsigned int memories = xed_decoded_inst_number_of_memory_operands(&d);
  for (unsigned int i = 0; i < memories; ++i) {
    append(&w, "%s{\"base\":\"%s\",\"index\":\"%s\",\"scale\":%u,"
      "\"segment\":\"%s\",\"displacement\":%lld,\"disp_width\":%u,"
      "\"address_width\":%u,\"length_bytes\":%u,\"read\":%s,\"written\":%s}",
      i ? "," : "", xed_reg_enum_t2str(xed_decoded_inst_get_base_reg(&d, i)),
      xed_reg_enum_t2str(xed_decoded_inst_get_index_reg(&d, i)),
      xed_decoded_inst_get_scale(&d, i),
      xed_reg_enum_t2str(xed_decoded_inst_get_seg_reg(&d, i)),
      (long long)xed_decoded_inst_get_memory_displacement(&d, i),
      xed_decoded_inst_get_memory_displacement_width_bits(&d, i),
      xed_decoded_inst_get_memop_address_width(&d, i),
      xed_decoded_inst_get_memory_operand_length(&d, i),
      xed_decoded_inst_mem_read(&d, i) ? "true" : "false",
      xed_decoded_inst_mem_written(&d, i) ? "true" : "false");
  }
  append(&w, "],\"register_operands\":[");
  const xed_inst_t *inst = xed_decoded_inst_inst(&d);
  unsigned int written = 0;
  for (unsigned int i = 0; i < xed_inst_noperands(inst); ++i) {
    const xed_operand_t *op = xed_inst_operand(inst, i);
    xed_operand_enum_t name = xed_operand_name(op);
    if (!xed_operand_is_register(name)) continue;
    append(&w, "%s{\"operand\":\"%s\",\"register\":\"%s\",\"visibility\":\"%s\"}",
      written++ ? "," : "", xed_operand_enum_t2str(name),
      xed_reg_enum_t2str(xed_decoded_inst_get_reg(&d, name)),
      xed_operand_visibility_enum_t2str(xed_operand_operand_visibility(op)));
  }
  append(&w, "]}");
  return w.failed ? -1 : (int)w.used;
}
