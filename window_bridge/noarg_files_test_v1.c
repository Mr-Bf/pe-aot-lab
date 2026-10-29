/* Real POSIX component tests only; no AppKit, PE, window or GPU. */
#include "noarg_files_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"check %u line %d failed errno=%d\n",checks,__LINE__,errno);return 1;}}while(0)
static int rejected(const char *base,const char *app,const char *id){NAFileSet f;int r=na_open_files(base,app,id,&f);if(r==0){na_close(&f);return 0;}return 1;}
int main(int argc,char **argv){
    if(argc!=2)return 64;char pattern[PATH_MAX];
    if(snprintf(pattern,sizeof pattern,"%s/noarg-files-XXXXXX",argv[1])>=(int)sizeof pattern)return 64;
    char *base=mkdtemp(pattern);if(!base)return 64;
    NAFileSet f;CHECK(na_open_files(base,"normal","run-1",&f)==0);
    struct stat st;CHECK(fstat(f.root,&st)==0&&(st.st_mode&07777)==0700&&st.st_uid==geteuid());
    CHECK(fstat(f.lock,&st)==0&&(st.st_mode&07777)==0600&&st.st_nlink==1);
    CHECK(na_write_exclusive(f.run,"started.json","{}\n",3)==0);
    CHECK(na_write_exclusive(f.run,"started.json","overwritten",11)<0&&errno==EEXIST);
    CHECK(na_write_exclusive(f.run,"../escape","bad",3)<0&&errno==EINVAL);
    CHECK(na_write_exclusive(f.data,"integer-tile.bin","guest-owned-marker",18)==0);
    pid_t child=fork();CHECK(child>=0);
    if(child==0){NAFileSet second;int r=na_open_files(base,"normal","run-child",&second);if(r==0)na_close(&second);_exit(r<0&&(errno==EWOULDBLOCK||errno==EAGAIN)?0:2);}
    int status=0;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    na_close(&f);CHECK(f.root==f.data&&f.data==f.runs&&f.runs==f.lock&&f.lock==f.run&&f.run==-1);
    CHECK(na_open_files(base,"normal","run-2",&f)==0);
    int saved=openat(f.data,"integer-tile.bin",O_RDONLY|O_NOFOLLOW);char bytes[19]={0};
    CHECK(saved>=0&&read(saved,bytes,18)==18&&!strcmp(bytes,"guest-owned-marker"));close(saved);na_close(&f);
    CHECK(rejected(base,"normal","run-2")); /* no overwrite of historical run */
    int root=na_open_absolute_directory(base);CHECK(root>=0);
    CHECK(mkdirat(root,"wide",0755)==0);CHECK(rejected(base,"wide","run"));
    CHECK(fstatat(root,"wide",&st,AT_SYMLINK_NOFOLLOW)==0&&(st.st_mode&07777)==0755);
    CHECK(symlinkat("normal",root,"app-link")==0);CHECK(rejected(base,"app-link","run"));
    char linked[PATH_MAX];CHECK(snprintf(linked,sizeof linked,"%s/app-link",base)<(int)sizeof linked);
    CHECK(na_open_absolute_directory(linked)<0); /* all absolute path components */
    CHECK(mkdirat(root,"data-link",0700)==0);int a=openat(root,"data-link",O_RDONLY|O_DIRECTORY);
    CHECK(a>=0&&symlinkat("../normal/Data",a,"Data")==0);close(a);CHECK(rejected(base,"data-link","run"));
    CHECK(mkdirat(root,"wide-data",0700)==0);a=openat(root,"wide-data",O_RDONLY|O_DIRECTORY);
    CHECK(a>=0&&mkdirat(a,"Data",0755)==0);close(a);CHECK(rejected(base,"wide-data","run"));
    CHECK(mkdirat(root,"lock-link",0700)==0);a=openat(root,"lock-link",O_RDONLY|O_DIRECTORY);
    CHECK(a>=0&&symlinkat("../normal/instance.lock",a,"instance.lock")==0);close(a);CHECK(rejected(base,"lock-link","run"));
    CHECK(mkdirat(root,"hard-lock",0700)==0);a=openat(root,"hard-lock",O_RDONLY|O_DIRECTORY);
    int l=openat(a,"original",O_WRONLY|O_CREAT|O_EXCL,0600);CHECK(l>=0);close(l);
    CHECK(linkat(a,"original",a,"instance.lock",0)==0);close(a);CHECK(rejected(base,"hard-lock","run"));
    CHECK(mkdirat(root,"fifo-lock",0700)==0);a=openat(root,"fifo-lock",O_RDONLY|O_DIRECTORY);
    CHECK(a>=0&&mkfifoat(a,"instance.lock",0600)==0);close(a);CHECK(rejected(base,"fifo-lock","run"));
    CHECK(mkdirat(root,"wide-lock",0700)==0);a=openat(root,"wide-lock",O_RDONLY|O_DIRECTORY);
    l=openat(a,"instance.lock",O_WRONLY|O_CREAT|O_EXCL,0644);CHECK(l>=0);close(l);close(a);CHECK(rejected(base,"wide-lock","run"));
    CHECK(rejected(base,"../escape","run"));CHECK(rejected(base,"normal","../escape"));
    char support[PATH_MAX];CHECK(snprintf(support,sizeof support,"%s/NewSupport",base)<(int)sizeof support);
    CHECK(na_open_files(support,"app","run",&f)==0);na_close(&f);
    CHECK(fstatat(root,"NewSupport",&st,AT_SYMLINK_NOFOLLOW)==0&&(st.st_mode&07777)==0700);
    CHECK(snprintf(support,sizeof support,"%s/app-link/NeverCreated",base)<(int)sizeof support);
    CHECK(rejected(support,"app","run"));
    a=openat(root,"normal",O_RDONLY|O_DIRECTORY);CHECK(a>=0);
    CHECK(fstatat(a,"NeverCreated",&st,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT);close(a);
    close(root);printf("{\"status\":\"PASS_FILES_COMPONENT_ONLY\",\"checks\":%u,\"guest_executions\":0,\"gui_executions\":0,\"gpu_executions\":0}\n",checks);return 0;
}
