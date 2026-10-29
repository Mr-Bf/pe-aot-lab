/* Read-only Foundation location and libproc identity query. No AppKit/events. */
#import <Foundation/Foundation.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static NSDictionary *identity(pid_t pid) {
    proc_bsdinfo a{},b{};char path[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&a,sizeof a)!=(int)sizeof a)return nil;
    if(proc_pidpath(pid,path,sizeof path)<=0)return nil;
    if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&b,sizeof b)!=(int)sizeof b)return nil;
    if(a.pbi_pid!=(uint32_t)pid||b.pbi_pid!=(uint32_t)pid||a.pbi_uid!=b.pbi_uid||
       a.pbi_start_tvsec!=b.pbi_start_tvsec||a.pbi_start_tvusec!=b.pbi_start_tvusec||
       b.pbi_status==SZOMB||b.pbi_uid!=geteuid())return nil;
    NSString *name=[[NSFileManager defaultManager] stringWithFileSystemRepresentation:path length:strlen(path)];
    if(!name)return nil;
    return @{@"pid":@(pid),@"uid":@(b.pbi_uid),@"ppid":@(b.pbi_ppid),@"path":name,
      @"start_seconds":@(b.pbi_start_tvsec),@"start_microseconds":@(b.pbi_start_tvusec)};
}
static int emit(id value) {
    NSError *error=nil;NSData *data=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:&error];
    if(!data)return 65;fwrite([data bytes],1,[data length],stdout);fputc('\n',stdout);return 0;
}
int main(int argc,char **argv) {
    @autoreleasepool {
        if(argc==2&&!strcmp(argv[1],"location")){
            NSURL *url=[[[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] firstObject];
            if(!url||![url isFileURL])return 66;
            return emit(@{@"support_directory":[url path],@"uid":@(geteuid()),@"query_pid":@(getpid()),
              @"scope":@"Foundation location only; no directory creation or AppKit"});
        }
        if(argc==3&&!strcmp(argv[1],"pid")){
            char *end=nullptr;errno=0;long pid=strtol(argv[2],&end,10);
            if(errno||!end||*end||pid<=1||pid>INT32_MAX)return 64;
            NSDictionary *value=identity((pid_t)pid);
            return value?emit(value):67;
        }
        if(argc==4&&!strcmp(argv[1],"find")){
            char *end=nullptr;errno=0;unsigned long long since=strtoull(argv[3],&end,10);
            if(errno||!end||*end)return 64;
            int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);if(bytes<=0||bytes>64*1024*1024)return 68;
            std::vector<pid_t> ids((size_t)bytes/sizeof(pid_t)+2048);
            int count=proc_listpids(PROC_ALL_PIDS,0,ids.data(),(int)(ids.size()*sizeof(pid_t)));
            if(count<=0||count>=(int)(ids.size()*sizeof(pid_t)))return 68;
            NSString *expected=[[NSFileManager defaultManager] stringWithFileSystemRepresentation:argv[2] length:strlen(argv[2])];
            NSMutableArray *matches=[NSMutableArray array];
            for(int i=0;i<count/(int)sizeof(pid_t);i++){
                NSDictionary *d=identity(ids[(size_t)i]);
                if(d&&[[d objectForKey:@"path"] isEqualToString:expected]&&
                   [[d objectForKey:@"start_seconds"] unsignedLongLongValue]>=since)[matches addObject:d];
            }
            return emit(@{@"matches":matches,@"scope":@"exact path and current UID only; unrelated process identities omitted"});
        }
        return 64;
    }
}
