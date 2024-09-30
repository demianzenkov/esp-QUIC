#ifndef _API_QUIC_H_
#define _API_QUIC_H_


#include "freertos/FreeRTOS.h"
#include "freertos/stream_buffer.h"

#include "quic_client_task.h"

#ifdef __cplusplus
extern "C" {
#endif


class QuicAPI {
public:
    QuicAPI();
    static void task(void * pvParameters);
    int         init();
    int         startClient(quic_client_params_t * quic_params);
private:
    int  handleFrame(uint8_t *data, int len);
    
public:
    QuicClientHandler * quic_client;
    
private:
    uint8_t * stream_buffer_local;
    uint8_t * stream_buffer_storage;

    StackType_t * quic_stack;
    StaticTask_t quic_task_handler;
    
    StreamBufferHandle_t quic_rx_stream_buffer;
    StaticStreamBuffer_t stream_buffer_struct;
};


#ifdef __cplusplus
}
#endif

#endif // _API_QUIC_H_