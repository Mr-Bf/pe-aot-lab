/* Versioned POSIX stubs derived from frozen file oracle SHA256 56fdd0a8f567fabe1217c11be5403471c329117f6b9939aa5f5280d744a6fced.
 * The ordinary binary protocol/5-argument main is omitted; process_entry is no-argument. */
/* Original PE bytes on x86/Rosetta, with restricted POSIX-backed Win64 stubs.
 * This is neither Windows nor Wine; only the documented file profile is used. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oracle_image.h"

typedef void *HANDLE;
typedef uint32_t DWORD;
typedef int32_t BOOL;
typedef struct { DWORD stage,error,written,read; } FileResult;
typedef struct { uintptr_t token; int fd; uint32_t access; dev_t device; ino_t inode; char name[121]; } OpenHandle;
static OpenHandle handles[32];
static uintptr_t next_token=0x60000000;
static _Thread_local DWORD last_error;
static uint32_t calls[5]; /* CreateFileA, WriteFile, ReadFile, CloseHandle, GetLastError */
static int root_fd=-1;
static void fail(const char *message){fprintf(stderr,"file oracle: %s\n",message);exit(2);}
static uint32_t error_code(int error) {
    switch(error){case ENOENT:return 2;case EACCES:case ELOOP:case EPERM:case EISDIR:case ENOTDIR:return 5;
        case EBADF:return 6;case ENOMEM:return 8;case EMFILE:case ENFILE:return 4;
        case EIO:return 23;case ENOSPC:case EDQUOT:return 112;case EINVAL:return 87;default:return 23;}
}
static int ascii_alnum(unsigned char c){return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9');}
static int valid_name(const char *name) {
    if(!name||!ascii_alnum((unsigned char)name[0]))return 0;
    size_t n=0;while(n<=120&&name[n]){unsigned char c=(unsigned char)name[n];if(!ascii_alnum(c)&&c!='.'&&c!='_'&&c!='-')return 0;n++;}
    if(!n||n>120||name[n-1]=='.'||strstr(name,".."))return 0;
    char stem[121];size_t end=0;
    while(end<n&&name[end]!='.'){unsigned char c=(unsigned char)name[end];stem[end]=(char)(c>='a'&&c<='z'?c-'a'+'A':c);end++;}
    stem[end]=0;
    if(!strcmp(stem,"CON")||!strcmp(stem,"PRN")||!strcmp(stem,"AUX")||!strcmp(stem,"NUL"))return 0;
    if(end==4&&(!memcmp(stem,"COM",3)||!memcmp(stem,"LPT",3))&&stem[3]>='1'&&stem[3]<='9')return 0;
    return 1;
}
static OpenHandle *lookup(HANDLE handle) {
    uintptr_t token=(uintptr_t)handle;
    for(unsigned i=0;i<32;i++)if(handles[i].token==token&&token)return &handles[i];
    return NULL;
}
static uint32_t live_handles(void){uint32_t n=0;for(unsigned i=0;i<32;i++)n+=handles[i].token!=0;return n;}

__attribute__((ms_abi,noinline)) static HANDLE win_create(const char *name,DWORD access,DWORD sharing,
    void *security,DWORD disposition,DWORD attributes,HANDLE template_file) {
    calls[0]++;
    if(sharing||security||template_file||attributes!=0x80||
       !((access==0x40000000u&&disposition==2)||(access==0x80000000u&&disposition==3))) {
        last_error=87;return (HANDLE)UINTPTR_MAX;
    }
    if(!valid_name(name)){last_error=123;return (HANDLE)UINTPTR_MAX;}
    unsigned slot=32;
    for(unsigned i=0;i<32;i++){
        if(handles[i].token&&!strcmp(handles[i].name,name)){last_error=32;return (HANDLE)UINTPTR_MAX;}
        if(!handles[i].token&&slot==32)slot=i;
    }
    if(slot==32){last_error=4;return (HANDLE)UINTPTR_MAX;}
    int existed=0,fd;
    if(disposition==2){
        fd=openat(root_fd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
        if(fd<0&&errno==EEXIST){existed=1;fd=openat(root_fd,name,O_WRONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);}
    }else fd=openat(root_fd,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0){last_error=error_code(errno);return (HANDLE)UINTPTR_MAX;}
    struct stat info;
    if(fstat(fd,&info)){DWORD error=error_code(errno);close(fd);last_error=error;return (HANDLE)UINTPTR_MAX;}
    if(!S_ISREG(info.st_mode)||info.st_nlink!=1){close(fd);last_error=5;return (HANDLE)UINTPTR_MAX;}
    for(unsigned i=0;i<32;i++)if(handles[i].token&&handles[i].device==info.st_dev&&handles[i].inode==info.st_ino){close(fd);last_error=32;return (HANDLE)UINTPTR_MAX;}
    if(disposition==2&&ftruncate(fd,0)){DWORD error=error_code(errno);close(fd);last_error=error;return (HANDLE)UINTPTR_MAX;}
    OpenHandle *entry=&handles[slot];entry->token=++next_token;entry->fd=fd;entry->access=access;entry->device=info.st_dev;entry->inode=info.st_ino;
    memcpy(entry->name,name,strlen(name)+1);
    if(disposition==2)last_error=existed?183:0;
    return (HANDLE)entry->token;
}
__attribute__((ms_abi,noinline)) static BOOL win_write(HANDLE handle,const void *buffer,DWORD size,DWORD *written,void *overlapped) {
    calls[1]++;if(written)*written=0;
    if(!written||overlapped||size>1048576||(!buffer&&size)){last_error=87;return 0;}
    OpenHandle *entry=lookup(handle);if(!entry){last_error=6;return 0;}
    if(entry->access!=0x40000000u){last_error=5;return 0;}
    ssize_t result;do{result=write(entry->fd,buffer,size);}while(result<0&&errno==EINTR);
    if(result<0){last_error=error_code(errno);return 0;}
    *written=(DWORD)result;return 1;
}
__attribute__((ms_abi,noinline)) static BOOL win_read(HANDLE handle,void *buffer,DWORD size,DWORD *read_count,void *overlapped) {
    calls[2]++;if(read_count)*read_count=0;
    if(!read_count||overlapped||size>1048576||(!buffer&&size)){last_error=87;return 0;}
    OpenHandle *entry=lookup(handle);if(!entry){last_error=6;return 0;}
    if(entry->access!=0x80000000u){last_error=5;return 0;}
    ssize_t result;do{result=read(entry->fd,buffer,size);}while(result<0&&errno==EINTR);
    if(result<0){last_error=error_code(errno);return 0;}
    *read_count=(DWORD)result;return 1;
}
__attribute__((ms_abi,noinline)) static BOOL win_close(HANDLE handle) {
    calls[3]++;OpenHandle *entry=lookup(handle);if(!entry){last_error=6;return 0;}
    int fd=entry->fd;entry->token=0;
    if(close(fd)){last_error=error_code(errno);return 0;}return 1;
}
__attribute__((ms_abi,noinline)) static DWORD win_error(void){calls[4]++;return last_error;}
