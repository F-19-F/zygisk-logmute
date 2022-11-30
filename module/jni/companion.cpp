//
// Created by TF19 on 2022/11/20.
//
#include <unistd.h>
#include <cstring>
#include <string>
#include <cstdlib>
#include <sys/inotify.h>
#include <dirent.h>
#include <fcntl.h>
#include <elf.h>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/stat.h>
#include "muteipc.h"
#include <thread>
using namespace std;
extern int nopLog(int pid);
extern unsigned long orig_code;
int elftype(pid_t pid);
bool isignore(pid_t pid);
[[noreturn]]
void mon();
void bootTrigger();
companion* controller;
static bool booted = false;
companion::companion() {
    LOGD("LogMute init");
    controller = this;
    nativeNop();
    thread t1(mon);
    t1.detach();
    thread t2(bootTrigger);
    t2.detach();
    LOGD("LogMute init done!");
//    LOGD("init loop done!");
}
void companion::nativeNop() {
    DIR* proc;
    dirent* tmp;
    pid_t  pid;
    proc = opendir("/proc");
    if(proc == nullptr){
        LOGD("open proc:%s", strerror(errno));
    }
    while ((tmp = readdir(proc))!=nullptr){
        pid = atoi(tmp->d_name);
        if(pid == getpid()){
            continue;
        }
        if(pid){
//            pids.insert(make_pair(pid, true));
            if(!isignore(pid)){
                int t = elftype(pid);
                if(t<0){
                    continue;
                }
#ifdef __arm__
                if( t != EM_ARM){
                    continue;
                }
#endif
#ifdef __aarch64__
                if (t != EM_AARCH64){
                    continue;
                }
#endif
                if(native_nop[pid]){
                    continue;
                }
                if(doMemNop(pid) != 0){
                    LOGD("NOP %d fail!",pid);
                }else{
                    this->native_nop[pid]= true;
//                    LOGD("NOP %d success!",pid);
                }
            }
        }
    }
    closedir(proc);
}
void companion::handler(int fd) {
    rootcmd cmd;
    cmdresult res;
    read(fd, &cmd, sizeof(cmd));
    switch (cmd.opcode) {
        case CMD_CHECK_POLICY:
            if(checkPolicy((char *)cmd.data)){
                res.result = RESULT_UNMUTE;
                *(unsigned long*)res.data = orig_code;
            } else{
                res.result = RESULT_MUTE;
            }
            break;
    }
    write(fd, &res, sizeof(res));
}
int companion::doMemNop(int pid) {
    return nopLog(pid);
}
void companion::setPolicy(std::string pkgname, bool sw) {
    policy[pkgname]=sw;
}
bool companion::checkPolicy(std::string pkgname) {
    auto r = this->policy.find(pkgname);
    if(r != this->policy.end()){
        return r->second;
    }
    return false;
}

bool isignore(pid_t pid){
    string p = "/proc/"+ to_string(pid)+"/exe";
    char buf[PATH_MAX] = {0};
    int size = readlink(p.c_str(),buf,PATH_MAX);
    if(size < 0){
//        LOGD("readlink: %s %s",p.c_str(), strerror(errno));
        return true;
    }
    buf[size] = '\0';
//    if(booted && strstr(buf,"/system/bin/app_process") != nullptr){
        if(booted && strstr(buf,"/system/bin/app_process") != nullptr){
            struct  stat s;
            stat(("/proc/"+ to_string(pid)).c_str(),&s);
//        非app进程
            if( s.st_uid> 1000 && s.st_uid < 10000){
//            LOGD("pid %d non normal app!",pid);
                return false;
            }
        }
//        return true;
//        int fd = open(("/proc/"+ to_string(pid) + "/cmdline").c_str(),O_RDONLY);
//        if(fd < 0){
//            LOGD("fd < 0 %s", strerror(errno));
//            return true;
//        }
//        char cmd[PATH_MAX] = {0};
//        read(fd,cmd,PATH_MAX);
//        close(fd);
//        if(strcmp(cmd,"zygote") == 0 || strcmp(cmd,"zygote64") == 0){
//            return false;
//        }
//    }
    if(strstr(buf,"/bin/adbd") != nullptr || strstr(buf,"magisk") != nullptr || strstr(buf,"/system/bin/init") != nullptr || strstr(buf,"logd") != nullptr){
        return true;
    }else{
        return false;
    }
}



int elftype(pid_t pid){
    string p = "/proc/"+ to_string(pid)+"/exe";
    int fd = open(p.c_str(),O_RDONLY);
    if(fd < 0){
//        LOGD("open: %s %s",p.c_str(), strerror(errno));
        return -1;
    }
    Elf64_Ehdr header;
    read(fd,&header,sizeof(Elf64_Ehdr));
    close(fd);
    return header.e_machine;
}
#define CONFIG_FILE "/data/local/tmp/log_whitelist.conf"
void createConfig(){
    fstream f(CONFIG_FILE,ios::out);
    f<<"# write log white pkgname list here \n";
    f.close();
    chmod(CONFIG_FILE,S_IREAD|S_IWRITE|S_IRGRP|S_IWGRP);
    chown(CONFIG_FILE,2000,2000);
}
void mon()
{
    int fd = inotify_init();
    if(inotify_add_watch(fd, CONFIG_FILE, IN_ATTRIB)<0){
        createConfig();
        inotify_add_watch(fd, CONFIG_FILE, IN_ATTRIB);
    }
    struct inotify_event *event;
    uint8_t buf[500];
    chmod(CONFIG_FILE,S_IREAD|S_IWRITE|S_IRGRP|S_IWGRP);
    while (true)
    {
        if (read(fd, buf, sizeof(buf)) < 0)
        {
            perror("read");
        }
        event = (struct inotify_event *)buf;
        fstream config(CONFIG_FILE,ios::in);
        if(!config){
            LOGD("CONFIG file not exists!Creating");
            createConfig();
            inotify_add_watch(fd,CONFIG_FILE,IN_ATTRIB);
        }
        LOGD("LOADING config files");
        string line;
        vector<string> whitelist;
        for( std::string line; getline( config, line ); ){
            if(!line.empty()){
                if(line[0]=='#'){
                    continue;
                }
                if(controller!= nullptr){
                    LOGD("add white %s",line.c_str());
                    whitelist.push_back(line);
                    controller->setPolicy(line,true);
                }
            }
        }
        for (auto i = controller->policy.begin(); i != controller->policy.end() ;) {
            auto r = find(whitelist.begin(),whitelist.end(),i->first);
            if(r==whitelist.end()){
                LOGD("remove %s",i->first.c_str());
                i = controller->policy.erase(i);
//                i->second = false;
            }else{
                ++i;
            }
        }
        config.close();
    }
}
void bootTrigger(){
    char buf[20]="0";
    while (true){
        __system_property_get("sys.boot_completed",buf);
        if(atoi(buf) == 1){
            LOGD("boot_completed");
            booted = true;
            controller->nativeNop();
            break;
        }
        sleep(1);
    }
}