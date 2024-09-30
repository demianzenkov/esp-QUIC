/* wifi_connect.c
 */

 #include "wifi_connect.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include <esp_wifi.h>
#include <esp_log.h>
#include "string.h"

const static char *TAG = "wifi_connect";

#define CONFIG_ESP_MAXIMUM_RETRY    5
#define DEFAULT_SCAN_LIST_SIZE      10

static EventGroupHandle_t s_wifi_event_group;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int s_retry_num = 0;


int WiFiConnect::connect(char * ssid, char * pwd)
{
    if(strlen(ssid) == 0) {
        ESP_LOGW(TAG, "ssid len is 0, using default");
        strcpy(ssid, CONFIG_DEFAULT_WIFI_SSID);
    }
    if(strlen(pwd) == 0) {
        ESP_LOGW(TAG, "pwd len is 0, using default");
        strcpy(pwd, CONFIG_DEFAULT_WIFI_PASSWORD);
    }

    if(!initialized) {
        init();
    };

    setNetwork(ssid, pwd);
    ESP_LOGI(TAG, "Starting wifi: %s, %s", ssid, pwd);
    startWiFi();
    startConnection();
    int status = waitForConnection();
    s_retry_num = 0;
    while((status != 0) && (s_retry_num < CONFIG_ESP_MAXIMUM_RETRY)) {
        ESP_LOGW(TAG, "Connection failed");
        vTaskDelay(1000);
        ESP_LOGI(TAG, "Restarting");
        startConnection();
        status = waitForConnection();
        s_retry_num++;
    }

    if(status != 0) {
        ESP_LOGE(TAG, "Failed to connect to wifi");
    } else {
        ESP_LOGI(TAG, "Connected to wifi");
    }

    return status;
}


static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if ((event_base == WIFI_EVENT) && (event_id == WIFI_EVENT_STA_DISCONNECTED)) {
        ESP_LOGD(TAG,"connect to the AP fail");
        xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    } else if ((event_base == IP_EVENT) && (event_id == IP_EVENT_STA_GOT_IP)) {
        ip_event_got_ip_t * event = (ip_event_got_ip_t*) event_data;
        WiFiConnect::printIP(event);
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

int WiFiConnect::waitForConnection() {
    int status = 0;
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdTRUE,
            pdFALSE,
            portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        status = 0;
    } else if (bits & WIFI_FAIL_BIT) {
        status = -1;
    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
        status = -2;
    }
   
    return status;
}

int WiFiConnect::init()
{
    int ret = 0;
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    initialized = true;                                                    
    return 0;
}

int WiFiConnect::setNetwork(char * _ssid, char * _pwd) {
    wifi_config_t wifi_config = {};
    strcpy((char *)wifi_config.sta.ssid, _ssid);
    strcpy((char *)wifi_config.sta.password, _pwd);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );

    return 0;
}

int WiFiConnect::startWiFi()
{
    if(!running) {
        ESP_ERROR_CHECK(esp_wifi_start());
    }

    running = true;
    return 0;
}

int WiFiConnect::stopWiFi()
{
    ESP_LOGI(TAG, "Stopping WiFi");
    if(running) {
        ESP_ERROR_CHECK(esp_wifi_stop());
    }
    running = false;
    return 0;
}

int WiFiConnect::startConnection() {
    return esp_wifi_connect();
}


/* Initialize Wi-Fi as sta and set scan method */
void WiFiConnect::scan(void)
{
    if(!initialized) {
        ESP_LOGW(TAG, "WiFi not initialized");
        init();
    }

    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));
   
    esp_wifi_scan_start(NULL, true);
    ESP_LOGI(TAG, "Max AP number ap_info can hold = %u", number);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);
    for (int i = 0; i < number; i++) {
        ESP_LOGI(TAG, "SSID \t\t%s", ap_info[i].ssid);
        ESP_LOGI(TAG, "RSSI \t\t%d", ap_info[i].rssi);
        printAuthMode(ap_info[i].authmode);
        if (ap_info[i].authmode != WIFI_AUTH_WEP) {
            printCipherType(ap_info[i].pairwise_cipher, ap_info[i].group_cipher);
        }
        ESP_LOGI(TAG, "Channel \t\t%d", ap_info[i].primary);
    }
}

int WiFiConnect::findAP(char * ssid)
{
    if(!initialized) {
        ESP_LOGW(TAG, "WiFi not initialized");
        init();
    }
    if(!running) {
        ESP_LOGW(TAG, "WiFi not running");
        startWiFi();
    }

    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));

    esp_wifi_scan_start(NULL, true);
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));

    ESP_LOGI(TAG, "Total APs scanned = %u/%u", ap_count, number);

    for (int i = 0; i < number; i++) {
        if(strcmp(ssid, (char *)ap_info[i].ssid) == 0) {
            ESP_LOGI(TAG, "Found AP: %s", ssid);
            return 0;
        }
    }

    ESP_LOGW(TAG, "AP not found: %s", ssid);
    return -1;
}

int WiFiConnect::printIP(ip_event_got_ip_t * event)
{
    ESP_LOGI(TAG, "IP: " IPSTR, IP2STR(&event->ip_info.ip));
    return 0;
}


void WiFiConnect::printAuthMode(int authmode)
{
    switch (authmode) {
    case WIFI_AUTH_OPEN:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OPEN");
        break;
    case WIFI_AUTH_OWE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_OWE");
        break;
    case WIFI_AUTH_WEP:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WEP");
        break;
    case WIFI_AUTH_WPA_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_PSK");
        break;
    case WIFI_AUTH_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_PSK");
        break;
    case WIFI_AUTH_WPA_WPA2_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA_WPA2_PSK");
        break;
    case WIFI_AUTH_ENTERPRISE:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_ENTERPRISE");
        break;
    case WIFI_AUTH_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA2_WPA3_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA2_WPA3_PSK");
        break;
    case WIFI_AUTH_WPA3_ENT_192:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_ENT_192");
        break;
    case WIFI_AUTH_WPA3_EXT_PSK:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_WPA3_EXT_PSK");
        break;
    default:
        ESP_LOGI(TAG, "Authmode \tWIFI_AUTH_UNKNOWN");
        break;
    }
}

void WiFiConnect::printCipherType(int pairwise_cipher, int group_cipher)
{
    switch (pairwise_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_AES_CMAC128:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_AES_CMAC128");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Pairwise Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }

    switch (group_cipher) {
    case WIFI_CIPHER_TYPE_NONE:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_NONE");
        break;
    case WIFI_CIPHER_TYPE_WEP40:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_WEP40");
        break;
    case WIFI_CIPHER_TYPE_WEP104:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_WEP104");
        break;
    case WIFI_CIPHER_TYPE_TKIP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP");
        break;
    case WIFI_CIPHER_TYPE_CCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_CCMP");
        break;
    case WIFI_CIPHER_TYPE_TKIP_CCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_TKIP_CCMP");
        break;
    case WIFI_CIPHER_TYPE_SMS4:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_SMS4");
        break;
    case WIFI_CIPHER_TYPE_GCMP:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_GCMP");
        break;
    case WIFI_CIPHER_TYPE_GCMP256:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_GCMP256");
        break;
    default:
        ESP_LOGI(TAG, "Group Cipher \tWIFI_CIPHER_TYPE_UNKNOWN");
        break;
    }
}
