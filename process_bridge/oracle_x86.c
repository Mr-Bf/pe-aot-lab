/* Test-only abrupt ExitProcess on the original x86 PE. No C++ or guest SEH
 * unwinding is performed. This is a POSIX model under Rosetta, not Windows. */
#include <setjmp.h>
#include "oracle_file_stubs.h"

static jmp_buf exit_environment;
static volatile uint32_t exit_called,exit_code,exit_calls;
__attribute__((ms_abi,noinline)) static void win_exit(DWORD code) {
    exit_called=1;exit_code=code;exit_calls++;
    longjmp(exit_environment,1);
}
typedef void (__attribute__((ms_abi)) *ProcessEntry)(void);

int main(int argc,char **argv) {
    if(argc!=3)fail("owned run directory and optional base hint required");
    root_fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root_fd<0)fail("open owned directory");
    char *end=NULL;errno=0;uint64_t hint=strtoull(argv[2],&end,0);
    if(errno||!end||*end||(hint&4095)||hint>UINTPTR_MAX-sizeof kImage)fail("invalid base hint");
    long page=sysconf(_SC_PAGESIZE);
    if(page<=0||page>4096||4096%(unsigned long)page)fail("host page cannot represent PE 4KiB permission boundaries");
    unsigned char *image=mmap((void *)(uintptr_t)hint,sizeof kImage,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(image==MAP_FAILED)fail("mmap image");memcpy(image,kImage,sizeof kImage);
    for(unsigned i=0;i<kRelocationCount;i++){
        uint64_t old;memcpy(&old,image+kRelocations[i],8);
        if(old<kPreferredBase||old>=kPreferredBase+sizeof kImage)fail("unexpected relocation value");
        uint64_t value=(uintptr_t)image+(old-kPreferredBase);memcpy(image+kRelocations[i],&value,8);
    }
    const uintptr_t targets[6]={(uintptr_t)&win_create,(uintptr_t)&win_write,(uintptr_t)&win_read,
        (uintptr_t)&win_close,(uintptr_t)&win_error,(uintptr_t)&win_exit};
    for(unsigned i=0;i<6;i++)if(kIatRvas[i])memcpy(image+kIatRvas[i],&targets[i],8);
    if(mprotect(image,sizeof kImage,PROT_NONE))fail("protect initial image gaps");
    for(unsigned i=0;i<kPageCount;i++){
        unsigned bits=kPagePermissions[i];
        if((bits&6)==6||!(bits&1))fail("unexpected W+X or unreadable page in known fixture");
        int permissions=((bits&1)?PROT_READ:0)|((bits&2)?PROT_WRITE:0)|((bits&4)?PROT_EXEC:0);
        if(mprotect(image+i*4096,4096,permissions))fail("set exact PE page permissions");
    }
    ProcessEntry entry=(ProcessEntry)(image+kEntryRva);
    last_error=0;memset(calls,0,sizeof calls);exit_called=exit_code=exit_calls=0;
    if(setjmp(exit_environment)==0)entry();
    uint32_t before_cleanup=live_handles(),cleanup_closes=0,cleanup_errors=0;
    for(unsigned i=0;i<32;i++)if(handles[i].token){
        if(close(handles[i].fd)==0)cleanup_closes++;else cleanup_errors++;
        handles[i].token=0;
    }
    int dump=openat(root_fd,"image-after.bin",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(dump<0)fail("open image observation");
    size_t position=0;
    while(position<sizeof kImage){ssize_t n=write(dump,image+position,sizeof kImage-position);if(n<0&&errno==EINTR)continue;if(n<=0)fail("write image observation");position+=(size_t)n;}
    if(close(dump))fail("close image observation");
    unsigned unchanged=memcmp(image+kTextRva,kImage+kTextRva,kTextSize)==0;
    printf("{\"outcome\":\"%s\",\"exit_code\":%" PRIu32 ",\"exit_calls\":%" PRIu32
           ",\"api_calls\":[%u,%u,%u,%u,%u,%u],\"open_handles_before_cleanup\":%u,\"cleanup_closes\":%u,"
           "\"cleanup_errors\":%u,\"open_handles_after_cleanup\":%u,\"last_error\":%u,\"host_page_size\":%ld,"
           "\"mapped_base\":%" PRIu64 ",\"requested_hint\":%" PRIu64 ",\"original_text_unchanged\":%u}\n",
           exit_called?"PROCESS_EXIT":"FUNCTION_RETURN",exit_code,exit_calls,calls[0],calls[1],calls[2],calls[3],calls[4],(unsigned)exit_calls,
           before_cleanup,cleanup_closes,cleanup_errors,live_handles(),last_error,page,(uint64_t)(uintptr_t)image,hint,unchanged);
    if(fflush(stdout)||munmap(image,sizeof kImage)||close(root_fd))fail("release process oracle resources");return 0;
}
