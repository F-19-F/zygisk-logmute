#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <pmparser.h>
#include "zygisk.hpp"
#include "muteipc.h"
using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;


extern void restoreFunArm(void *addr, uint8_t *code,off_t len);
extern void restoreFunArm64(void* addr, uint8_t *code,off_t len);
class LogMute : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        preSpecialize(process);
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        preSpecialize("system_server");
    }

private:
    Api *api;
    JNIEnv *env;

    void preSpecialize(const char *process) {
        // Demonstrate connecting to to companion process
        // We ask the companion for a random number
        int fd = api->connectCompanion();
        cmdresult res;
        rootcmd cmd = {0};
        cmd.opcode = CMD_CHECK_POLICY;
        strcpy((char *)cmd.data,process);
        write(fd,&cmd,sizeof(cmd));
        read(fd, &res, sizeof(res));
        close(fd);
        if(res.result != RESULT_UNMUTE){
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        unsigned long code = *(unsigned long *)res.data;
        void* handle = dlopen("liblog.so",RTLD_NOW);

        if(handle == NULL){
            LOGD("handle = NULL");
            return;
        }
        void* funPtr = dlsym(handle,"__android_log_logd_logger");
        if(funPtr == NULL){
            LOGD("funPtr = NULL");
            return;
        }
        procmaps_struct* maps_tmp=NULL;
        procmaps_iterator* maps = pmparser_parse(-1);
        if(maps==NULL){
            LOGD("[map]: cannot parse the memory map");
            return;
        }
// makes address writable
        while( (maps_tmp = pmparser_next(maps)) != NULL){
            if((void *)funPtr >  maps_tmp->addr_start && (void *)funPtr < maps_tmp->addr_end){
                // pmparser_print(maps_tmp,0);
                // +w
                if (mprotect(maps_tmp->addr_start,maps_tmp->length,PROT_EXEC|PROT_WRITE|PROT_READ) != 0){
                    LOGD("mprotect : %s", strerror(errno));
                    break;
                }
// write original code
#ifdef __arm__
                restoreFunArm(funPtr,res.data,res.len);
#endif
#ifdef __aarch64__
                restoreFunArm64(funPtr,res.data,res.len);
#endif
                // -w
                if (mprotect(maps_tmp->addr_start,maps_tmp->length,PROT_EXEC|PROT_READ) != 0){
                    LOGD("mprotect : %s", strerror(errno));
                    break;
                }
                break;
            }
        }
        pmparser_free(maps);


        // Since we do not hook any functions, we should let Zygisk dlclose ourselves
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

};
// run in zygiskd with root privileges
static companion *impl;
static void companion_handler(int i) {
    if(impl == nullptr){
        impl = new companion();
    }
    impl->handler(i);
}

REGISTER_ZYGISK_MODULE(LogMute)
REGISTER_ZYGISK_COMPANION(companion_handler)
