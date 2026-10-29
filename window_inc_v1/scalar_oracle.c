/* Controlled original-PE-byte x86 harness. No guest operation is reimplemented.
 * Raw image/code bytes come from the generated fixture header. No Windows or
 * hardware fault/SEH emulation; negative guest-memory cases are ARM contracts. */
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include "scalar_image.h"
typedef struct { uint64_t gpr[16],rflags; } InputFrame;
typedef struct { uint64_t gpr[16],rflags,rip; } OutputFrame;
uint64_t oracle_host_rsp,oracle_entry_address;
OutputFrame oracle_output;
extern void oracle_run(InputFrame *);
extern void oracle_capture(void);
static void fail(const char *s) { fprintf(stderr,"oracle failure: %s\n",s);exit(2); }
static void read_exact(void *p,size_t n) { if(fread(p,1,n,stdin)!=n)fail("truncated request"); }
static void write_exact(const void *p,size_t n) { if(fwrite(p,1,n,stdout)!=n)fail("response write"); }
int main(void) {
    int translated=0;size_t size=sizeof translated;
    int query=sysctlbyname("sysctl.proc_translated",&translated,&size,NULL,0);
    if(query || translated!=1) {
        fprintf(stderr,"translation query: return=%d errno=%d value=%d size=%zu\n",query,errno,translated,size);
        fail("expected Rosetta x86 test process");
    }
    long page=sysconf(_SC_PAGESIZE);
    if(page<=0||page>4096||4096%(unsigned long)page)fail("host page granularity");
    unsigned char *image=mmap(NULL,sizeof kImage,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(image==MAP_FAILED)fail("mmap");
    memcpy(image,kImage,sizeof kImage);
    if(mprotect(image,sizeof kImage,PROT_NONE))fail("protect image");
    for(unsigned n=0;n<sizeof kPermissions;n++) {
        int flags=((kPermissions[n]&1)?PROT_READ:0)|((kPermissions[n]&2)?PROT_WRITE:0)|((kPermissions[n]&4)?PROT_EXEC:0);
        if(mprotect(image+4096*n,4096,flags))fail("set image permissions");
    }
    oracle_entry_address=(uint64_t)(uintptr_t)(image+0x1000);
    unsigned char stack[4096],before[4096];unsigned count=0;
    for(;;) {
        char magic[8];size_t got=fread(magic,1,8,stdin);
        if(!got&&feof(stdin))break;
        if(got!=8||memcmp(magic,"SCAIN001",8))fail("request magic");
        InputFrame input;read_exact(&input,sizeof input);
        read_exact(image+0x2000,8192);
        if(memcmp(image+0x1000,kImage+0x1000,kCodeSize))fail("raw guest code identity before");
        uint64_t logical_rsp=input.gpr[4];
        if(logical_rsp>UINT64_MAX-8)fail("logical RSP overflow");
        memset(stack,0x5a,sizeof stack);
        uintptr_t host_rsp=((uintptr_t)(stack+2048)&~(uintptr_t)15)+(logical_rsp&15);
        uint64_t capture=(uint64_t)(uintptr_t)&oracle_capture;
        memcpy((void*)host_rsp,&capture,8);memcpy(before,stack,sizeof stack);
        uint64_t logical_target=0,native_target=(uint64_t)(uintptr_t)(image+0x2ffe);
        if(kBaseRegister<16) {
            uint64_t logical_data=0;logical_target=input.gpr[kBaseRegister];
            memcpy(&logical_data,image+0x2000,8);
            if(kBaseRegister==4||logical_target!=logical_data+0xffe)fail("logical target identity");
            input.gpr[kBaseRegister]=native_target;
        }
        input.gpr[4]=host_rsp;input.rflags=2;memset(&oracle_output,0,sizeof oracle_output);
        oracle_run(&input);
        if(oracle_output.rip!=capture||oracle_output.gpr[4]!=host_rsp+8)fail("actual guest RET/capture");
        if(memcmp(before,stack,sizeof stack))fail("guest leaf modified stack");
        if(memcmp(image+0x1000,kImage+0x1000,kCodeSize))fail("raw guest code identity after");
        if(kBaseRegister<16) {
            if(oracle_output.gpr[kBaseRegister]!=native_target)fail("INC changed address register");
            oracle_output.gpr[kBaseRegister]=logical_target;
        }
        oracle_output.gpr[4]=logical_rsp+8;oracle_output.rip=UINT64_C(0x7fff00000000);
        write_exact("SCAOUT01",8);write_exact(&oracle_output,sizeof oracle_output);write_exact(image+0x2000,8192);count++;
    }
    if(fflush(stdout))fail("flush");
    fprintf(stderr,"{\"status\":\"RAW_X86_PASS\",\"cases\":%u,\"translated\":1,\"raw_pe_code_identity\":true}\n",count);
    if(munmap(image,sizeof kImage))fail("munmap");
    return 0;
}
