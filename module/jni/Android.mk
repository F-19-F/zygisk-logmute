LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := logmute
LOCAL_SRC_FILES := main.cpp nopFun.cpp
LOCAL_STATIC_LIBRARIES := libcxx pmparser
LOCAL_C_INCLUDES := pmparser
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include jni/libcxx/Android.mk
include jni/proc_maps_parser/Android.mk
# If you do not want to use libc++, link to system stdc++
# so that you can at least call the new operator in your code

# include $(CLEAR_VARS)
# LOCAL_MODULE := example
# LOCAL_SRC_FILES := example.cpp
# LOCAL_LDLIBS := -llog -lstdc++
# include $(BUILD_SHARED_LIBRARY)
