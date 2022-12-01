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
//#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "LogMuter", __VA_ARGS__)
off_t orig_len = 0;
u_int8_t* backup_code = nullptr;
static u_int8_t* patch_code = nullptr;
void genPatchAndBackup(void * addr);
static u_int8_t arm64_paciasp_array[4] = {0x3f,0x23,0x03,0xd5};
static u_int8_t arm64_autiasp_array[4] = {0xbf,0x23,0x03,0xd5};
static u_int8_t arm64_nop_array[4] = {0x1f,0x20,0x03,0xd5};
// nop nop nop ret
static u_int8_t arm64_ret_array[4] = {0xc0,0x03,0x5f,0xd6};
//static u_int8_t arm64_ret_array_pac[8] = {0x1f,0x20,0x03,0xd5,0xc0,0x03,0x5f,0xd6};
// bx lr bx lr
static u_int8_t thumb_ret_array[4] = {0x70,0x47,0x70,0x47};
static u_int8_t arm_ret_array[4] = {0x1e,0xff,0x2f,0xe1};
void restoreFunArm64(void* addr, uint8_t *code,off_t len){
    memcpy(addr,code,len);
}
void restoreFunArm(void *addr, uint8_t *code,off_t len){
    if((off_t)addr % 2 != 0){
        memcpy((void *)((off_t )addr - 1),code,len);
    } else{
        memcpy((void *)addr,code,len);
    }
}
int ptrace_writedata(pid_t pid, uint8_t *pWriteAddr, uint8_t *pWriteData, size_t size) {
    long nWriteCount = 0;
    long nRemainCount = 0;
    uint8_t *pCurSrcBuf = pWriteData;
    uint8_t *pCurDestBuf = pWriteAddr;
    long lTmpBuf = 0;
    long i = 0;

    nWriteCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);

    for (i = 0; i < nWriteCount; i++) {
        memcpy((void *)(&lTmpBuf), pCurSrcBuf, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, (void *)pCurDestBuf, (void *)lTmpBuf) < 0) {
            return -1;
        }
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }

    if (nRemainCount > 0) {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurDestBuf, NULL);
        memcpy((void *)(&lTmpBuf), pCurSrcBuf, nRemainCount);
        if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0){
            return -1;
        }
    }
    return 0;
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
    if((off_t)addr % 2 != 0){
        if(ptrace_writedata(pid,(uint8_t*)((off_t)addr-1),patch_code,orig_len) == 0){
            ret = 0;
        }
    } else{
        if(ptrace_writedata(pid,(uint8_t*)addr,patch_code,orig_len) == 0){
            ret = 0;
        }
    }

#endif
#ifdef __aarch64__
    if(ptrace_writedata(pid,(uint8_t*)addr,patch_code,orig_len) == 0){
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
    if(patch_code == nullptr){
        genPatchAndBackup(fun);
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
//unsigned long ptrace_read(void * addr){
//
//}
void genPatchAndBackup(void * addr){
#ifdef __arm__
    orig_len = 4;
    backup_code = (uint8_t *) malloc(orig_len);
    patch_code = (uint8_t *) malloc(orig_len);
    if((off_t)addr % 2 !=0){
        memcpy(backup_code,(void *)((off_t)addr - 1),orig_len);
        *(uint32_t*) patch_code = *(uint32_t*)thumb_ret_array;
    } else{
        memcpy(backup_code,(void *)addr,orig_len);
        *(uint32_t*) patch_code = *(uint32_t*)arm_ret_array;
    }
#endif
#ifdef __aarch64__
    void * begin = addr;
    u_int32_t arm64_paciasp = *(u_int32_t *)arm64_paciasp_array;
    u_int32_t arm64_autiasp = *(u_int32_t *)arm64_autiasp_array;
    u_int32_t arm64_nop = *(u_int32_t *)arm64_nop_array;
    u_int32_t arm64_ret = *(u_int32_t *)arm64_ret_array;
    u_int32_t head = arm64_nop;
    u_int32_t end = arm64_ret;
    if(*(uint32_t *)begin == arm64_paciasp) {
        head = arm64_paciasp;
        end = arm64_autiasp;
    }
//        begin = (void *)((off_t)begin + 4);
    orig_len += 4;
    while (*(uint32_t *) begin != end) {
        orig_len += 4;
        // printf("loop once\n");
        begin = (void *) ((off_t) begin + 4);
    }
    backup_code = (uint8_t *) malloc(orig_len);
    memcpy(backup_code, addr, orig_len);
    patch_code = (uint8_t *) malloc(orig_len);
    uint32_t *tmp = (uint32_t *) patch_code;
    tmp[0] = head;
    tmp[orig_len / 4 - 1] = end;
    for (int i = 1; i < orig_len / 4 - 1; i++) {
        tmp[i] = arm64_nop;
    }
#endif

//    } else{
//        orig_len = 8;
//        backup_code = (uint8_t *) malloc(orig_len);
//        patch_code = (uint8_t *) malloc(orig_len);
//        memcpy(backup_code,addr,orig_len);
//        *(uint32_t*)patch_code = *(uint32_t*)thumb_ret_array;
//    }
//    int noplen = 0;
//    uint32_t ibuf,end;
//    end = arm64_ret;
    // paciasp
    // o
    // o
    // autiasp
    // ret
//    while (read(fd,&ibuf,sizeof(ibuf)) == sizeof(ibuf))
//    {
//        if(ibuf == arm64_paciasp){
//            end = arm64_autiasp;
//            begin+=4;
//            continue;
//        }
//        if(ibuf == end){
//            break;
//        }
//        noplen++;
//    }
//    uint32_t *wbuf = (uint32_t*)malloc(noplen*sizeof(uint32_t));
//    for(int i = 0;i<noplen;i++){
//        wbuf[i]=arm64_nop;
//    }
//    if(lseek(fd,begin,SEEK_SET) < 0){
//        fprintf(stderr,"lseek : %s\n",strerror(errno));
//        return -1;
//    }
//    write(fd,wbuf,noplen*sizeof(uint32_t));
//    free(wbuf);
//    return 0;
//#ifdef __aarch64__

//#endif
}