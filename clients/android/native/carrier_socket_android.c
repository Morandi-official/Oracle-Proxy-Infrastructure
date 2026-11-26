// SPDX-License-Identifier: Apache-2.0
#include <jni.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#ifndef UDP_GRO
#define UDP_GRO 104
#endif

JNIEXPORT jintArray JNICALL
Java_org_morandi_proxy_ProxyVpnService_carrierReceiveOptionsForTest(
        JNIEnv *env, jclass type, jint fd) {
    (void)type;
    jint options[2] = {-1, -1};
    int value;
    socklen_t size = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &size) == 0 &&
            size == sizeof(value) && value > 0) {
        options[0] = value;
    }
    size = sizeof(value);
    if (getsockopt(fd, IPPROTO_UDP, UDP_GRO, &value, &size) == 0 &&
            size == sizeof(value) && (value == 0 || value == 1)) {
        options[1] = value;
    }
    jintArray result = (*env)->NewIntArray(env, 2);
    if (result != NULL) {
        (*env)->SetIntArrayRegion(env, result, 0, 2, options);
    }
    return result;
}
