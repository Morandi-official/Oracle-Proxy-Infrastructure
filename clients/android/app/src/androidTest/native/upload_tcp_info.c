// SPDX-License-Identifier: Apache-2.0
#include <jni.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

// The instrumentation APK passes a duplicate of an app-owned TCP descriptor.
JNIEXPORT jlongArray JNICALL
Java_org_morandi_proxy_MatchedUploadControl_readTcpInfo(JNIEnv *env, jclass type, jint fd) {
    (void)type;
    struct tcp_info info = {0};
    socklen_t size = sizeof(info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &size) < 0 ||
            size < offsetof(struct tcp_info, tcpi_segs_out) + sizeof(info.tcpi_segs_out)) {
        return NULL;
    }
    jlong counters[] = {(jlong)info.tcpi_bytes_acked, info.tcpi_total_retrans, info.tcpi_segs_out};
    jlongArray result = (*env)->NewLongArray(env, 3);
    if (result != NULL) (*env)->SetLongArrayRegion(env, result, 0, 3, counters);
    return result;
}
