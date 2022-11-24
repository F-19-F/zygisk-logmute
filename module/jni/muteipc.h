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
    char data[100];
} rootcmd;
typedef struct {
    int result;
} cmdresult;

class companion {
public:
    companion();
    void handler(int fd);
    int checkPolicy(std::string pkgname);
    int doMemNop(int pid);
private:
    std::map<pid_t ,bool> pids;
    int ifd;
};
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "LogMuter", __VA_ARGS__)
#endif //ZYGISK_LOGMUTE_MUTEIPC_H
