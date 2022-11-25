#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <android/log.h>
#include <unistd.h>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <pmparser.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "muteipc.h"
static u_int8_t arm64_paciasp_array[4] = {0x3f,0x23,0x03,0xd5};
static u_int8_t arm64_autiasp_array[4] = {0xbf,0x23,0x03,0xd5};
static u_int8_t arm64_nop_array[4] = {0x1f,0x20,0x03,0xd5};
static u_int8_t arm64_ret_array[4] = {0xc0,0x03,0x5f,0xd6};
void nopFunArm64(void* addr){
    u_int32_t arm64_paciasp = *(u_int32_t *)arm64_paciasp_array;
    u_int32_t arm64_autiasp = *(u_int32_t *)arm64_autiasp_array;
    u_int32_t arm64_nop = *(u_int32_t *)arm64_nop_array;
    u_int32_t arm64_ret = *(u_int32_t *)arm64_ret_array;
    u_int32_t* begin = (uint32_t*) addr;
    u_int32_t end = arm64_ret;
    if(*begin == arm64_paciasp){
        begin+=1;
        end = arm64_autiasp;
    }
    int i = 0;
    while (*begin!=end)
    {
        i++;
        *begin = arm64_nop;
        begin++;
    }
}
int memNopArm64(int fd,void* addr){
    uint64_t begin = (uint64_t) addr;
    if(lseek(fd,begin,SEEK_SET) < 0){
        fprintf(stderr,"lseek : %s\n",strerror(errno));
        return -1;
    }
    u_int32_t arm64_paciasp = *(u_int32_t *)arm64_paciasp_array;
    u_int32_t arm64_autiasp = *(u_int32_t *)arm64_autiasp_array;
    u_int32_t arm64_nop = *(u_int32_t *)arm64_nop_array;
    u_int32_t arm64_ret = *(u_int32_t *)arm64_ret_array;
    int noplen = 0;
    uint32_t ibuf,end;
    end = arm64_ret;
    // paciasp
    // o
    // o
    // autiasp
    // ret
    while (read(fd,&ibuf,sizeof(ibuf)) == sizeof(ibuf))
    {
        if(ibuf == arm64_paciasp){
            end = arm64_autiasp;
            begin+=4;
            continue;
        }
        if(ibuf == end){
            break;
        }
        noplen++;
    }
    uint32_t *wbuf = (uint32_t*)malloc(noplen*sizeof(uint32_t));
    for(int i = 0;i<noplen;i++){
        wbuf[i]=arm64_nop;
    }
    if(lseek(fd,begin,SEEK_SET) < 0){
        fprintf(stderr,"lseek : %s\n",strerror(errno));
        return -1;
    }
    write(fd,wbuf,noplen*sizeof(uint32_t));
    free(wbuf);
    return 0;
}
int do_nop(int pid,void* addr){
//#define USE_PTRACE
#ifdef USE_PTRACE
    int stat = 0;
    if(ptrace(PTRACE_ATTACH,pid) < 0){
        perror("PTRACE_ATTACH");
        return -1;
    }
    waitpid(pid,&stat,WUNTRACED);
#else
    if(kill(pid,19)!=0){
        perror("kill-19");
        return -1;
    }
    usleep(1000);
#endif
    char buf[50] = {0};
    sprintf(buf,"/proc/%d/mem",pid);
    int fd = open(buf,O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr,"open proc mem : %s\n",strerror(errno));
    }
//    不支持
#ifndef __aarch64__
close(fd);
return -1;
#endif
    if(memNopArm64(fd,addr)<0){
        return -1;
    }
    close(fd);
#ifdef USE_PTRACE
    if(ptrace(PTRACE_DETACH,pid,NULL,0) < 0){
        perror("PTRACE_DETACH");
        return -1;
    }
#else
    if(kill(pid,18)!=0){
        perror("kill-18");
        return -1;
    }
#endif
    return 0;
}
int getAddrMap(void *p,int pid,procmaps_struct *res){
    int ret = -1;
    procmaps_struct* maps_tmp=NULL;
    // // foo();
    procmaps_iterator* maps = pmparser_parse(pid);
    if(maps==NULL){
//        LOGD("sopid = %d",getpid());
        LOGD("maps==NULL");
        fprintf (stderr,"[map]: cannot parse the memory map of %d\n",pid);
        return -1;
    }
    while( (maps_tmp = pmparser_next(maps)) != NULL){
        if((void *)p >  maps_tmp->addr_start && (void *)p < maps_tmp->addr_end){
            *res = *maps_tmp;
            ret = 0;
            LOGD("addr found");
            break;
        }
    }
    pmparser_free(maps);

    return ret;
}
int getOffset(const char* dlname,const char* symbol,uint64_t* res){
    void* handle = dlopen(dlname,RTLD_NOW);
    if(handle == NULL){
        LOGD("dlopen error");
        perror("dlopen");
        return -1;
    }
    void* fun = dlsym(handle,symbol);
    if(fun == NULL){
        LOGD("dlsym error");
        perror("dlsym");
        return -1;
    }
    procmaps_struct local_map;
    if(getAddrMap(fun,-1,&local_map)){
        LOGD("getAddrMap error");
        fprintf(stderr,"getAddrMap error\n");
        return -1;
    }
    fprintf(stdout,"handle = 0x%" PRIx64 "\n",(uint64_t)handle);
    fprintf(stdout,"map_start = 0x%" PRIx64 "\n",(uint64_t)local_map.addr_start);
    fprintf(stdout,"fun_start = 0x%" PRIx64 "\n",(uint64_t)fun);
    *res = (uint64_t)fun - (uint64_t)local_map.addr_start;
    return 0;

}
int findXMapByname(int pid,procmaps_struct *res,const char* pattern){
    int ret = -1;
    procmaps_struct* maps_tmp=NULL;
    procmaps_iterator* maps = pmparser_parse(pid);
    if(maps==NULL){
        LOGD("findXMapByname:maps==NULL");
        fprintf (stderr,"[map]: cannot parse the memory map of %d\n",pid);
        return -1;
    }
    while( (maps_tmp = pmparser_next(maps)) != NULL){
        if(maps_tmp->is_x && strstr(maps_tmp->pathname,pattern)!=NULL){
            *res = *maps_tmp;
            ret = 0;
            break;
        }
    }
    pmparser_free(maps);
    return ret;
}
int getRemoteAddr(int pid,const char* dlname,const char* symbol,uint64_t* res){
    static uint64_t offset = 0;
    if(offset == 0 && getOffset(dlname,symbol,&offset)<0){
//        LOGD("getRemoteAddr :offset error!");
        return -1;
    }
    procmaps_struct remote_map;
    if(findXMapByname(pid,&remote_map,dlname)){
//        LOGD("getRemoteAddr :findXMapByname error!");
        fprintf(stderr,"findXMapByname not found\n");
        return -1;
    }
    fprintf(stdout,"remote_map_start = 0x%" PRIx64 "\n",(uint64_t)remote_map.addr_start);
    *res = (uint64_t)remote_map.addr_start + offset;
    return 0;
}
#define TARGET_LIBRARY "liblog.so"
#define TARGET_SYMBOL "__android_log_logd_logger"
int nopLog(int pid){
    uint64_t rmote_addr;
    if(getRemoteAddr(pid,TARGET_LIBRARY,TARGET_SYMBOL,&rmote_addr)<0){
//        LOGD("getRemoteAddr fail!");
        return -1;
    }
    return do_nop(pid,(void *)rmote_addr);
}