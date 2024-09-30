#include "esp_log.h"
#include "esp_heap_trace.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "quic_api.h"
#include "wifi_connect.h"


extern "C" void app_main(void)
{
    esp_log_level_set("wifi", ESP_LOG_WARN);
    esp_log_level_set("wifi_init", ESP_LOG_WARN);
    
    ESP_ERROR_CHECK(nvs_flash_init());

    WiFiConnect wifi;
    QuicAPI quic;
}
