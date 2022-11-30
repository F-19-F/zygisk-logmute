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
unsigned long orig_code = 0;
unsigned long backup(void * addr);
// nop nop nop ret
static u_int8_t arm64_ret_array[8] = {0x1f,0x20,0x03,0xd5,0xc0,0x03,0x5f,0xd6};
// bx lr bx lr
static u_int8_t thumb_ret_array[4] = {0x70,0x47,0x70,0x47};
static u_int8_t arm_ret_array[4] = {0x1e,0xff,0x2f,0xe1};
void restoreFunArm64(void* addr, unsigned long code){
    *(unsigned long*)addr = code;
//    *(uint64_t*)addr = *(uint64_t*)arm64_ret_array;
}
void restoreFunArm(void *addr, unsigned long code){
    if((off_t)addr % 2 != 0){
        *(unsigned long*)((off_t )addr - 1) = code;
    } else{
        *(unsigned long *)addr = code;
    }

}
int do_nop(int pid,void* addr){
    int stat = 0;
    int ret = -1;
    if(ptrace(PTRACE_ATTACH,pid) < 0){
        perror("PTRACE_ATTACH");
        return -1;
    }
    waitpid(pid,&stat,WUNTRACED);
#ifdef __arm__
    unsigned long wbuf = 0;
    if((off_t)addr % 2 != 0){
        wbuf = *(uint32_t*)thumb_ret_array;
        if (ptrace(PTRACE_POKETEXT,pid,(void *)((off_t) addr -1),wbuf) == 0){
            ret = 0;
        }
    }else{
        wbuf = *(uint32_t*)arm_ret_array;
        if (ptrace(PTRACE_POKETEXT,pid,addr,wbuf) == 0){
            ret = 0;
        }
    }

#endif
#ifdef  __aarch64__
    unsigned long wbuf = *(uint64_t*)arm64_ret_array;
    if(ptrace(PTRACE_POKETEXT,pid,addr,wbuf) == 0){
        ret = 0;
    }
#endif
    if(ptrace(PTRACE_DETACH,pid,NULL,0) < 0){
        perror("PTRACE_DETACH");
        return ret;
    }
    return ret;
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
    if(orig_code == 0){
        orig_code = backup(fun);
    }
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
//    fprintf(stdout,"remote_fun_start = 0x%" PRIx64 "\n",(uint64_t)rmote_addr);
    return do_nop(pid,(void *)rmote_addr);
}
unsigned long backup(void * addr){
    if((off_t)addr % 2 !=0){
        return *(unsigned long *)((off_t)addr - 1);
    } else{
        return *(unsigned long *)addr;
    }
}