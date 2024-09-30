idf_component_register( SRC_DIRS "."
                        INCLUDE_DIRS "." 
                        REQUIRES 
                            wolfssl
                            ngtcp2
                            esp_timer
                            lwip
                            quic-api
                        )

                        