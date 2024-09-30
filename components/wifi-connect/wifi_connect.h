/* wifi_connect.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
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