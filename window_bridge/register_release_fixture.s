// Derive the full guest VA of existing Release method signature 101 from import 8.
// This must still be rejected by IAT_REG64 even if that method thunk is RX C3.
.text
.globl guest_entry
guest_entry:
  pushq %r14
  subq $32,%rsp
  movq __imp_GetLastError(%rip),%r14
  addq $0x5d000,%r14
.globl register_call
register_call:
  callq *%r14
.globl after_register_call
after_register_call:
  movl %eax,%ecx
  callq *__imp_ExitProcess(%rip)
  movl $0xdeadbeef,after_exit(%rip)
  addq $32,%rsp
  popq %r14
  retq
.data
.globl after_exit
after_exit: .long 0
