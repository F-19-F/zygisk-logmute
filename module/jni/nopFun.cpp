#include <sys/types.h>
#include <android/log.h>
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
