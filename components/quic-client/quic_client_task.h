#ifndef _QUIC_SIMPLE_CLIENT_TASK_H_
#define _QUIC_SIMPLE_CLIENT_TASK_H_


#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    StreamBufferHandle_t rx_stream_buf;
    char * quic_host;
    char * quic_port;
} quic_client_params_t;


class QuicClientHandler {
public:
    int createTask(quic_client_params_t * quic_params);
    static void task(void * pvParameters);
private:
    quic_client_params_t * quic_params;

public:
    SemaphoreHandle_t need_reconnect_sem;
    SemaphoreHandle_t send_sync_sem;
    SemaphoreHandle_t quic_to_os_sync_sem;
    SemaphoreHandle_t client_connected_sem;
    SemaphoreHandle_t quic_exit_sem;
    uint8_t * timesync_buf;
    size_t timesync_len;
};

#ifdef __cplusplus
}
#endif

#endif // _QUIC_SIMPLE_CLIENT_TASK_H_
