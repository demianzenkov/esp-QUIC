idf_component_register( SRC_DIRS ./ 
                        INCLUDE_DIRS ./ 
                        REQUIRES 
                            esp_netif
                            esp-tls
                            nvs_flash
                            http_parser
                            esp_http_client
                            quic-client
                        )