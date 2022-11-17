#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/mman.h>
#include <pmparser.h>
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "Magisk", __VA_ARGS__)
extern void nopFunArm64(void* addr);
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
#ifndef  __LP64__
        LOGD("non 64");
        return;
#endif
        // Demonstrate connecting to to companion process
        // We ask the companion for a random number
        unsigned r = 0;
        int fd = api->connectCompanion();
        read(fd, &r, sizeof(r));
        close(fd);
        LOGD("example: process=[%s], r=[%u]\n", process, r);
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
        while( (maps_tmp = pmparser_next(maps)) != NULL){
            if((void *)funPtr >  maps_tmp->addr_start && (void *)funPtr < maps_tmp->addr_end){
                // pmparser_print(maps_tmp,0);
                // +w
                if (mprotect(maps_tmp->addr_start,maps_tmp->length,PROT_EXEC|PROT_WRITE|PROT_READ) != 0){
                    LOGD("mprotect : %s", strerror(errno));
                    break;
                }
                nopFunArm64(funPtr);
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

static int urandom = -1;

static void companion_handler(int i) {
    if (urandom < 0) {
        urandom = open("/dev/urandom", O_RDONLY);
    }
    unsigned r;
    read(urandom, &r, sizeof(r));
    LOGD("example: companion r=[%u]\n", r);
    write(i, &r, sizeof(r));
}

REGISTER_ZYGISK_MODULE(LogMute)
REGISTER_ZYGISK_COMPANION(companion_handler)
