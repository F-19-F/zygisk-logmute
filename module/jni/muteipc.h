//
// Created by TF19 on 2022/11/20.
//

#ifndef ZYGISK_LOGMUTE_MUTEIPC_H
#define ZYGISK_LOGMUTE_MUTEIPC_H
#include <string>
#include <android/log.h>
#include <map>
enum {
    CMD_CHECK_POLICY
};
enum {
    RESULT_MUTE,
    RESULT_UNMUTE
};
typedef struct {
    int opcode;
    uint8_t data[100];
} rootcmd;
typedef struct {
    int result;
    off_t len;
    uint8_t data[1000];
} cmdresult;

class companion {
public:
    companion();
    void handler(int fd);
    bool checkPolicy(std::string pkgname);
    void setPolicy(std::string pkgname,bool sw);
    int doMemNop(int pid);
    std::map<std::string ,bool> policy;
    std::map<pid_t,bool> native_nop;
    void nativeNop();
};
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "LogMuter", __VA_ARGS__)
#endif //ZYGISK_LOGMUTE_MUTEIPC_H
