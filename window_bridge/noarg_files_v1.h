#ifndef PE_AOT_NOARG_FILES_V1_H
#define PE_AOT_NOARG_FILES_V1_H
/* Private local App data and a whole-guest-session lock; no guest state access.
 * Existing parent directories are never chmod'ed. Not an adversarial same-UID
 * filesystem sandbox; the private application directory is a trusted root. */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/file.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {int root,data,runs,lock,run;} NAFileSet;
static void na_init(NAFileSet *f){f->root=f->data=f->runs=f->lock=f->run=-1;}
static void na_close(NAFileSet *f){
    int *fds[]={&f->run,&f->data,&f->runs,&f->lock,&f->root};
    for(size_t i=0;i<sizeof fds/sizeof *fds;i++)if(*fds[i]>=0){close(*fds[i]);*fds[i]=-1;}
}
static bool na_component(const char *s){
    if(!s||!*s||strlen(s)>NAME_MAX||!strcmp(s,".")||!strcmp(s,".."))return false;
    for(const unsigned char *p=(const unsigned char *)s;*p;p++)if(*p=='/'||*p<32)return false;
    return true;
}
static bool na_empty_acl(int fd){
    errno=0;acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
    /* Darwin represents an absent extended ACL as NULL/ENOENT. The descriptor
     * has already passed fstat; all other ACL-query failures remain errors. */
    if(!acl)return errno==ENOENT;
    if(acl_valid(acl)!=0){int error=errno;acl_free(acl);errno=error;return false;}
    acl_entry_t entry;errno=0;int result=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry),error=errno;
    acl_free(acl);
    /* Darwin returns 0 for an entry and -1/EINVAL for the end of a valid ACL,
     * unlike the Linux 1/0 convention. A failed ACL read is not empty. */
    if(result==-1&&error==EINVAL)return true;
    errno=EACCES;return false;
}
static int na_open_absolute_directory(const char *path){
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX){errno=EINVAL;return -1;}
    char copy[PATH_MAX];memcpy(copy,path,strlen(path)+1);
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)return -1;
    char *cursor=copy+1;
    while(*cursor){
        char *end=strchr(cursor,'/');if(end)*end='\0';
        if(!na_component(cursor)){close(fd);errno=EINVAL;return -1;}
        int next=openat(fd,cursor,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        int error=errno;close(fd);if(next<0){errno=error;return -1;}fd=next;
        if(!end)break;cursor=end+1;
    }
    return fd;
}
static int na_open_support_directory(const char *path){
    /* Foundation supplies a location only. Open every parent without following
     * links before creating the final standard directory, if it is absent. */
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX){errno=EINVAL;return -1;}
    char parent[PATH_MAX];memcpy(parent,path,strlen(path)+1);
    char *slash=strrchr(parent,'/');
    if(!slash||!na_component(slash+1)){errno=EINVAL;return -1;}
    char name[NAME_MAX+1];memcpy(name,slash+1,strlen(slash+1)+1);
    if(slash==parent)slash[1]='\0';else *slash='\0';
    int fd=na_open_absolute_directory(parent);if(fd<0)return -1;
    if(mkdirat(fd,name,0700)!=0&&errno!=EEXIST){int error=errno;close(fd);errno=error;return -1;}
    int result=openat(fd,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),error=errno;close(fd);
    if(result<0){errno=error;return -1;}
    struct stat st;if(fstat(result,&st)!=0){error=errno;close(result);errno=error;return -1;}
    if(!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()){close(result);errno=EACCES;return -1;}
    return result;
}
static int na_private_directory(int parent,const char *name,bool exclusive){
    if(!na_component(name)){errno=EINVAL;return -1;}
    if(mkdirat(parent,name,0700)!=0 && (exclusive||errno!=EEXIST))return -1;
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return -1;
    struct stat st;
    if(fstat(fd,&st)!=0){int error=errno;close(fd);errno=error;return -1;}
    if(!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&07777)!=0700){close(fd);errno=EACCES;return -1;}
    if(!na_empty_acl(fd)){int error=errno;close(fd);errno=error;return -1;}
    return fd;
}
static int na_open_files(const char *support,const char *application,const char *run_id,NAFileSet *f){
    na_init(f);
    if(!na_component(application)||!na_component(run_id)){errno=EINVAL;return -1;}
    int base=na_open_support_directory(support);if(base<0)return -1;
    f->root=na_private_directory(base,application,false);int error=errno;close(base);
    if(f->root<0){errno=error;return -1;}
    f->lock=openat(f->root,"instance.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if(f->lock<0)goto failed;
    struct stat st;
    if(fstat(f->lock,&st)!=0)goto failed;
    if(!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||(st.st_mode&07777)!=0600){errno=EACCES;goto failed;}
    if(!na_empty_acl(f->lock))goto failed;
    if(flock(f->lock,LOCK_EX|LOCK_NB)!=0)goto failed;
    f->data=na_private_directory(f->root,"Data",false);if(f->data<0)goto failed;
    f->runs=na_private_directory(f->root,"Runs",false);if(f->runs<0)goto failed;
    f->run=na_private_directory(f->runs,run_id,true);if(f->run<0)goto failed;
    return 0;
failed:
    error=errno;na_close(f);errno=error;return -1;
}
static int na_write_exclusive(int directory,const char *name,const void *bytes,size_t size){
    if(!na_component(name)||(size&&!bytes)){errno=EINVAL;return -1;}
    int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;
    const unsigned char *p=(const unsigned char *)bytes;size_t at=0;
    while(at<size){ssize_t n=write(fd,p+at,size-at);if(n<0&&errno==EINTR)continue;
        if(n<=0){int error=n<0?errno:EIO;close(fd);errno=error;return -1;}at+=(size_t)n;}
    if(fsync(fd)!=0){int error=errno;close(fd);errno=error;return -1;}
    return close(fd);
}
#endif
