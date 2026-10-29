/* MIT, self-authored CLI integration input. Build for Win64, then translate PE.
 * No map, symbols, source or expected state is provided to the converter.
 * Each real PE execution reads the previous counter and saves the next value.
 */
typedef unsigned int DWORD;
typedef int BOOL;
typedef void *HANDLE;
#define IMPORT __declspec(dllimport)
#define INVALID ((HANDLE)(unsigned long long)-1)
IMPORT HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
IMPORT BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
IMPORT BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
IMPORT BOOL CloseHandle(HANDLE);
IMPORT DWORD GetLastError(void);
IMPORT void ExitProcess(DWORD);
static const char name[]="migration-counter.bin";
const void *counter_anchor=name;
static DWORD value,count;

void migration_entry(void) {
    DWORD error=0;
    HANDLE file=CreateFileA(name,0x80000000u,0,0,3,0x80,0);
    if(file==INVALID) {
        if(GetLastError()!=2) { ExitProcess(11); return; }
    } else {
        if(!ReadFile(file,&value,4,&count,0) || count!=4 || value>1000) error=12;
        if(!CloseHandle(file)) error=13;
        if(error) { ExitProcess(error); return; }
    }
    value+=1;
    file=CreateFileA(name,0x40000000u,0,0,2,0x80,0);
    if(file==INVALID) { ExitProcess(14); return; }
    if(!WriteFile(file,&value,4,&count,0) || count!=4) error=15;
    if(!CloseHandle(file)) error=16;
    ExitProcess(error);
}
