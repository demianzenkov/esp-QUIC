#include "quic_api.h"
#include "quic_client_task.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"



static const char *TAG = "api_quic";

QuicAPI::QuicAPI() {
}


int QuicAPI::init()
{
    quic_client = new QuicClientHandler();

    ESP_LOGW(TAG, "Starting QuicAPI client");
    
    stream_buffer_local = (uint8_t *)heap_caps_malloc(4096, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    

    stream_buffer_storage = (uint8_t *)heap_caps_malloc(16*1024 + 1, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    quic_rx_stream_buffer = xStreamBufferCreateStatic(16*1024, 1024, stream_buffer_storage, &stream_buffer_struct);
    if(quic_rx_stream_buffer == NULL) {
        ESP_LOGE(TAG, "Failed to create quic_rx_stream_buffer");
        return -1;
    }

    quic_stack = (StackType_t *)heap_caps_malloc(32 * 1024, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if (quic_stack == NULL) {
        ESP_LOGE(TAG, "Failed to allocate quic_stack");
        return -1;
    }
    
    xTaskCreateStatic(task, "quic_task", 32 * 1024, this, 5, quic_stack, &quic_task_handler);
    return 0;
}


int QuicAPI::startClient(quic_client_params_t * quic_params)
{
    quic_params->rx_stream_buf = quic_rx_stream_buffer;

    int ret = quic_client->createTask(quic_params);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to start quic client");
        return ret;
    }
    return 0;
}


void QuicAPI::task(void * pvParameters)
{
    QuicAPI * p_this = (QuicAPI *)pvParameters;
    while (1) {
        if(p_this->quic_rx_stream_buffer == NULL) {
            continue;
        }
        
        int bytes_received = xStreamBufferReceive(p_this->quic_rx_stream_buffer, p_this->stream_buffer_local, 1024, pdMS_TO_TICKS(1));
        if(!bytes_received)
            continue;
        
        ESP_LOGD(TAG, "QUIC received %d", bytes_received);
        int status = p_this->handleFrame(p_this->stream_buffer_local, bytes_received);
    }
}


int QuicAPI::handleFrame(uint8_t * data, int len) 
{   
    ESP_LOGD("QUIC", "Received %d bytes", len);
    // Add quic frame handler here
    return 0;
}
