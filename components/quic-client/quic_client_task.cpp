#include "quic_client.h"
#include "quic_client_task.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_timer.h"

static const char *TAG = "quic_client_task";

static struct client quic_client = {};
StackType_t * quic_stack;
StaticTask_t quic_task_handler;
// SemaphoreHandle_t quic_exit_sem;


int QuicClientHandler::createTask(quic_client_params_t * quic_params_p) 
{
    quic_params = quic_params_p;
    timesync_buf = new uint8_t[16];

    need_reconnect_sem = xSemaphoreCreateBinary();
    if (need_reconnect_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create need_reconnect_sem");
        return -1;
    }

    send_sync_sem = xSemaphoreCreateBinary();
    if (send_sync_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create send_sync_sem");
        return -1;
    }

    quic_to_os_sync_sem = xSemaphoreCreateBinary();
    if (quic_to_os_sync_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create quic_to_os_sync_sem");
        return -1;
    }

    client_connected_sem = xSemaphoreCreateBinary();
    if (client_connected_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create client_connected_sem");
        return -1;
    }

    quic_exit_sem = xSemaphoreCreateBinary();
    if (quic_exit_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create quic_exit_sem");
        return -1;
    }

    quic_stack = (StackType_t *)heap_caps_malloc(32 * 1024, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if (quic_stack == NULL) {
        ESP_LOGE(TAG, "Failed to allocate quic_stack");
        return -1;
    }
    
    xTaskCreateStatic(task, "quic_client_task", 32 * 1024, this, 5, quic_stack, &quic_task_handler);
    
    return 0;
}


void QuicClientHandler::task(void *pvParameters) 
{
    QuicClientHandler * p_this = (QuicClientHandler *)pvParameters;

    ESP_LOGD(TAG, "Connecting to host: %s, port: %s", p_this->quic_params->quic_host, p_this->quic_params->quic_port);
    
    if(QuicClient::init(&quic_client, p_this->quic_params->rx_stream_buf, p_this->quic_params->quic_host, p_this->quic_params->quic_port)) {
        ESP_LOGE(TAG, "client_init failed");
        vTaskDelete(NULL);
    };



    int ret = 0;
    while(1) {
        ret = QuicClient::read(&quic_client);
        if (ret != 0) {
            if(ret == NGTCP2_ERR_DRAINING) {
                ESP_LOGI(TAG, "client_read draining, reconnecting");
                xSemaphoreGive(p_this->need_reconnect_sem);
            } else {
                ESP_LOGI(TAG, "client_read failed, closing connection");
            }
            break;
        }

        if (QuicClient::write(&quic_client) != 0) {
            ESP_LOGI(TAG, "client_write failed, closing connection");
            break;
        }
        if(xSemaphoreTake(p_this->quic_exit_sem, 0)) {
            ESP_LOGI(TAG, "exit sem, closing connection");
            break;
        }

        if (xSemaphoreTake(p_this->send_sync_sem, 0)) {
            ESP_LOGD(TAG, "sync sem taken");
            quic_client.stream.data = p_this->timesync_buf;
            quic_client.stream.datalen = p_this->timesync_len;
            quic_client.stream.nwrite = 0;
            xSemaphoreGive(p_this->quic_to_os_sync_sem);
        }
    }

    QuicClient::close(&quic_client);
    QuicClient::clean(&quic_client);
    
    vSemaphoreDelete(p_this->quic_exit_sem);
    vSemaphoreDelete(p_this->send_sync_sem);
    vSemaphoreDelete(p_this->need_reconnect_sem);
    vSemaphoreDelete(p_this->client_connected_sem);
    vTaskDelete(NULL);
    free(quic_stack);
    free(p_this->timesync_buf);
    ESP_LOGW(TAG, "quic_client_task deleted");
}
