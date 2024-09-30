/* wifi_connect.h
 */

#ifndef WIFI_CONNECT_H
#define WIFI_CONNECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <esp_idf_version.h>
#include <esp_log.h>
#include <esp_wifi.h>

class WiFiConnect {
public:
    int         connect(char * ssid, char * pwd);
    int         init();
    int         startWiFi();
    int         stopWiFi();
    int         waitForConnection();
    int         startConnection();
    int         setNetwork(char * _ssid, char * _pwd);
    void        scan();
    int         findAP(char * ssid);
    static int  printIP(ip_event_got_ip_t * event);
    static void printAuthMode(int authmode);
    static void printCipherType(int pairwise_cipher, int group_cipher);
private:
    esp_netif_t * sta_netif;
    bool initialized = false;
    bool running = false;
    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
};

#ifdef __cplusplus
}
#endif


#endif /* _WIFI_CONNECT_H_ */