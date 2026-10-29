/* SysV host entry, arbitrary guest GPR frame, original PE bytes at runtime-mapped oracle_entry_address.
 * Single-threaded test process only. All capture stores precede flag-changing ops.
 * Capture switches back to the saved host stack BEFORE pushfq: guest stack stays intact.
 */
.text
.p2align 4
.globl _oracle_run
_oracle_run:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, _oracle_host_rsp(%rip)
    pushq 128(%rdi)
    popfq
    movq 0(%rdi), %rax
    movq 8(%rdi), %rcx
    movq 16(%rdi), %rdx
    movq 24(%rdi), %rbx
    movq 40(%rdi), %rbp
    movq 48(%rdi), %rsi
    movq 64(%rdi), %r8
    movq 72(%rdi), %r9
    movq 80(%rdi), %r10
    movq 88(%rdi), %r11
    movq 96(%rdi), %r12
    movq 104(%rdi), %r13
    movq 112(%rdi), %r14
    movq 120(%rdi), %r15
    movq 32(%rdi), %rsp
    movq 56(%rdi), %rdi
    jmp *_oracle_entry_address(%rip)

.globl _oracle_capture
_oracle_capture:
    movq %rax, _oracle_output+0(%rip)
    movq %rcx, _oracle_output+8(%rip)
    movq %rdx, _oracle_output+16(%rip)
    movq %rbx, _oracle_output+24(%rip)
    movq %rsp, _oracle_output+32(%rip)
    movq %rbp, _oracle_output+40(%rip)
    movq %rsi, _oracle_output+48(%rip)
    movq %rdi, _oracle_output+56(%rip)
    movq %r8, _oracle_output+64(%rip)
    movq %r9, _oracle_output+72(%rip)
    movq %r10, _oracle_output+80(%rip)
    movq %r11, _oracle_output+88(%rip)
    movq %r12, _oracle_output+96(%rip)
    movq %r13, _oracle_output+104(%rip)
    movq %r14, _oracle_output+112(%rip)
    movq %r15, _oracle_output+120(%rip)
    movq _oracle_host_rsp(%rip), %rsp
    pushfq
    popq _oracle_output+128(%rip)
    leaq _oracle_capture(%rip), %rax
    movq %rax, _oracle_output+136(%rip)
    cld
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
