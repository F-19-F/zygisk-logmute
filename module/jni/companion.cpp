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
#include "muteipc.h"
#include <thread>
using namespace std;
extern int nopLog(int pid);
bool is64elf(pid_t pid);
bool isignore(pid_t pid);
[[noreturn]]
void mon();
companion::companion() {
    LOGD("LogMute init");
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
            pids.insert(make_pair(pid, true));
            if(!isignore(pid)){
                if(!is64elf(pid)){
                    continue;
                }
                if(doMemNop(pid) != 0){
                    LOGD("NOP %d fail!",pid);
                }else{
                    LOGD("NOP %d success!",pid);
                }
            }
        }
    }
//    thread t1(mon);
//    t1.detach();
    LOGD("init loop done!");
    closedir(proc);

}

void companion::handler(int fd) {
    rootcmd cmd;
    cmdresult res;
    read(fd, &cmd, sizeof(cmd));
    switch (cmd.opcode) {
        case CMD_CHECK_POLICY:
            if(strstr(cmd.data, "powerkeeper") != NULL){
                res.result = RESULT_UNMUTE;
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



bool isignore(pid_t pid){
    string p = "/proc/"+ to_string(pid)+"/exe";
    char buf[PATH_MAX] = {0};
    int size = readlink(p.c_str(),buf,PATH_MAX);
    if(size < 0){
//        LOGD("readlink: %s %s",p.c_str(), strerror(errno));
        return false;
    }
    buf[size] = '\0';
    if(strstr(buf,"/system/bin/app_process") != nullptr || strstr(buf,"/bin/adbd") != nullptr || strstr(buf,"magisk") != nullptr || strstr(buf,"init") != nullptr || strstr(buf,"logd") != nullptr || strstr(buf,"lmkd") != nullptr){
        return true;
    }else{
        return false;
    }
}



bool is64elf(pid_t pid){
    string p = "/proc/"+ to_string(pid)+"/exe";
    int fd = open(p.c_str(),O_RDONLY);
    if(fd < 0){
//        LOGD("open: %s %s",p.c_str(), strerror(errno));
        return false;
    }
    Elf64_Ehdr header;
    read(fd,&header,sizeof(Elf64_Ehdr));
    close(fd);
    if(header.e_machine == EM_AARCH64 || header.e_machine == EM_X86_64){
        return true;
    }else{
        return false;
    }
}

int binarySearch(int* arr,int val,int len){
    if(len == 0){
        return -1;
    }
    int left = 0,right = len;
    int i = (left+right)/2,next;
    while (1)
    {
        if(val > arr[i]){
            left = i;
        }else if (val < arr[i])
        {
            right = i;
        }else{
            return 0;
        }
        next = (left+right)/2;
        if (next == i)
        {
            return -1;
        }
        i = next;
    }


}
#define SEQ_SIZE 100000
#define TLINKER "/system/bin/linker64"
[[noreturn]]
void mon()
{
    int fd = inotify_init();
    inotify_add_watch(fd, TLINKER, IN_OPEN);
    struct inotify_event *event;
    uint8_t buf[500];
    int i = 0;
    int oldlen = 0;
    DIR *d;
    struct dirent *subp;
    pid_t old_pids[SEQ_SIZE],new_pids[SEQ_SIZE];
    // treeNode btree[BTREESIZE] = {0};
    int pid;
    // if (d== NULL)
    // {
    //     fprintf(stderr,"d == NULL\n");
    //     return -1;
    // }
    struct timeval tv;
    gettimeofday(&tv,NULL);
    time_t t_last = tv.tv_sec,t_now = 0;
    while (true)
    {
        int ct = 0;
        if (read(fd, buf, sizeof(buf)) < 0)
        {
            perror("read");
        }
        gettimeofday(&tv,NULL);
        t_now = tv.tv_sec;
        if(t_now - t_last <= 1){
            // fprintf(stdout,"too short %ld \n",t_now - t_last);
            continue;
        }
        event = (struct inotify_event *)buf;
        if (event->mask & IN_OPEN)
        {
            ++i;
            // fprintf(stdout, "open%d\n", i);
        }
        d = opendir("/proc");
        while ((subp = readdir(d))!=NULL)
        {
            pid = atoi(subp->d_name);
            if (subp != NULL && pid)
            {
                // fprintf(stdout,"pid = %d\n",pid);
                if(binarySearch(old_pids,pid,oldlen) != 0){
                    if(!isignore(pid)){
                        if(is64elf(pid)){
                            LOGD("nop new process %d",pid);
                            nopLog(pid);
                        }
                    }
                    // fprintf(stdout,"new pid:%d\n",pid);
                }
                new_pids[ct++] = pid;
            }
        }
        // fprintf(stdout, "sum:%d\n", ct);
        memcpy(old_pids,new_pids,ct*sizeof(pid_t));
        t_last = t_now;
        oldlen = ct;
        closedir(d);
        /* code */
    }
}