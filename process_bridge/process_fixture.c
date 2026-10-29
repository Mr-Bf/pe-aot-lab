/* Ordinary no-argument Windows-target entry with all business data in the PE.
 * ExitProcess deliberately has no compiler noreturn annotation: the after_exit
 * test must retain its following operations so runtime termination is tested. */
typedef unsigned int DWORD;
typedef int BOOL;
typedef unsigned long long U64;
typedef void *HANDLE;
typedef struct {DWORD stage,win32_error,bytes_written,bytes_read;} FileResult;
#define IMPORT __declspec(dllimport)
IMPORT HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
IMPORT BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT DWORD GetLastError(void);
IMPORT void ExitProcess(DWORD);
extern U64 file_roundtrip(const char *,const unsigned char *,unsigned char *,DWORD,volatile FileResult *);

const char process_filename[]="process-save.bin";
const unsigned char process_source[67]="PE process_entry: static buffers, real file APIs, guest exit.\n";
const unsigned char process_after_source[]="MUST-NOT-RUN\n";
const DWORD process_source_size=sizeof process_source;
unsigned char process_destination[67];
volatile FileResult process_result;
volatile DWORD process_marker;
volatile DWORD process_caller_marker;
DWORD process_written;
DWORD process_after_written;
HANDLE process_handle;
volatile U64 process_return_code;
const void *process_image_anchor=process_filename;
_Static_assert(sizeof(FileResult)==16 && sizeof(HANDLE)==8 && sizeof(DWORD)==4,"Win64 data layout");

#if PROCESS_VARIANT == 3
__declspec(noinline) void process_exit_helper(void) {
    ExitProcess(0x87654321u);
    process_marker=0xa5a55a5au;
    process_result.stage=0xeeu;
    (void)WriteFile(process_handle,process_after_source,sizeof process_after_source-1,
                    &process_after_written,(void *)0);
}
#endif

__declspec(noinline) void process_entry(void) {
#if PROCESS_VARIANT == 1
    U64 result=file_roundtrip(process_filename,process_source,process_destination,
                             sizeof process_source,&process_result);
    process_return_code=result;
    ExitProcess((DWORD)result);
#elif PROCESS_VARIANT == 2 || PROCESS_VARIANT == 3
    process_result.stage=1;
    HANDLE handle=CreateFileA(process_filename,0x40000000u,0,(void *)0,2,0x80,(HANDLE)0);
    process_handle=handle;
    if(handle==(HANDLE)(U64)-1){process_result.win32_error=GetLastError();ExitProcess(1);return;}
    process_result.stage=2;
    if(!WriteFile(handle,process_source,sizeof process_source,&process_written,(void *)0)) {
        process_result.win32_error=GetLastError();ExitProcess(2);return;
    }
    process_result.bytes_written=process_written;
    if(process_written!=sizeof process_source){ExitProcess(3);return;}
    process_result.stage=3;
#if PROCESS_VARIANT == 2
    ExitProcess(0x12345678u);
#else
    process_exit_helper();
    /* Runtime exit must also prevent resuming this real guest caller. */
    process_caller_marker=0xc0dec0deu;
#endif
#elif PROCESS_VARIANT == 4
    return;
#else
#error Select PROCESS_VARIANT 1..4
#endif
}
