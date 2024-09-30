#include "esp_timer.h"
#include "quic_client.h"
#include <time.h>
#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "openssl/err.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "ngtcp2/ngtcp2_crypto_wolfssl.h"
#include "stream_buffer.h"


#include <ngtcp2/ngtcp2.h>

#define QUIC_LOGS_ENABLED   0
#define ALPN                "\x09alpn-name" // first byte is length of ALPN string

static const char *TAG = "quic";


static StreamBufferHandle_t quic_rx_streambuf;

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  // Assuming LOG_TAG is defined elsewhere, or you can replace it with your desired tag
  esp_log_writev(ESP_LOG_INFO, TAG, fmt, args);

  va_end(args);
}


static uint64_t timestamp(void) {
  struct timespec tp = {};              

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    ESP_LOGE(TAG, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  } else {
    ESP_LOGD(TAG, "timestamp ns: %lu", tp.tv_nsec);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}



static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) 
{
    ESP_LOGD(TAG, "extend_max_local_streams_bidi");
    
    static uint8_t request_message_buf[KEY_BUF_SIZE];

    struct client *c = (struct client *)user_data;
    int rv;
    int64_t stream_id;
    (void)max_streams;

    if (c->stream.stream_id != -1) {
        return 0;
    }

    rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
    if (rv != 0) {
        return 0;
    }

    c->stream.stream_id = stream_id;

    size_t message_length;
    bool status;
    
    // message_length = stream.bytes_written;
    // ESP_LOGD(TAG, "Encoding OK, message_length: %i", message_length);
    // uint16_t len = message_length + 3;
    // request_message_buf[0] = FRAME_SUBSCRIPTION;
    // request_message_buf[1] = len & 0xFF;
    // request_message_buf[2] = (len >> 8) & 0xFF;
    // // memcpy(request_message_buf+3, proto_buffer, message_length);
    // c->stream.data = (const uint8_t *)request_message_buf;
    // c->stream.datalen = len;
    // ESP_LOGD(TAG, "send request(%i)", len);


    return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  size_t i;
  (void)rand_ctx;

  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)random();
  }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}



int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {
    ESP_LOGD(TAG, "recv_stream_data: %u", datalen);
    if(xStreamBufferSend(quic_rx_streambuf, (void *)data, datalen, 0) != datalen) {
        ESP_LOGE(TAG, "xStreamBufferSend failed");
    }
    
    return 0;
}

static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {
    ngtcp2_path path = {
        {
            (struct sockaddr *)local_addr,
            local_addrlen,
        },
        {
            (struct sockaddr *)remote_addr,
            remote_addrlen,
        },
        NULL,
    };
    ngtcp2_callbacks callbacks = {
        ngtcp2_crypto_client_initial_cb,
        NULL, /* recv_client_initial */
        ngtcp2_crypto_recv_crypto_data_cb,
        NULL, /* handshake_completed */
        NULL, /* recv_version_negotiation */
        ngtcp2_crypto_encrypt_cb,
        ngtcp2_crypto_decrypt_cb,
        ngtcp2_crypto_hp_mask_cb,
        recv_stream_data, /* recv_stream_data */
        NULL, /* acked_stream_data_offset */
        NULL, /* stream_open */
        NULL, /* stream_close */    // TODO - check this callback for session closing
        NULL, /* recv_stateless_reset */
        ngtcp2_crypto_recv_retry_cb,
        extend_max_local_streams_bidi,
        NULL, /* extend_max_local_streams_uni */
        rand_cb,
        get_new_connection_id_cb,
        NULL, /* remove_connection_id */
        ngtcp2_crypto_update_key_cb,
        NULL, /* path_validation */
        NULL, /* select_preferred_address */
        NULL, /* stream_reset */
        NULL, /* extend_max_remote_streams_bidi */
        NULL, /* extend_max_remote_streams_uni */
        NULL, /* extend_max_stream_data */
        NULL, /* dcid_status */
        NULL, /* handshake_confirmed */
        NULL, /* recv_new_token */
        ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        NULL, /* recv_datagram */
        NULL, /* ack_datagram */
        NULL, /* lost_datagram */
        ngtcp2_crypto_get_path_challenge_data_cb,
        NULL, /* stream_stop_sending */
        ngtcp2_crypto_version_negotiation_cb,
        NULL, /* recv_rx_key */
        NULL, /* recv_tx_key */
        NULL, /* early_data_rejected */
    };
    ngtcp2_cid dcid, scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv;

    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    scid.datalen = 8;
    if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return -1;
    }

    ngtcp2_settings_default(&settings);

    settings.initial_ts = timestamp();
    #if(QUIC_LOGS_ENABLED)
    settings.log_printf = log_printf;
    #endif

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_bidi_local = NGTCP2_MAX_VARINT;
    params.initial_max_data = NGTCP2_MAX_VARINT;

    rv =
        ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                                &callbacks, &settings, &params, NULL, c);
    if (rv != 0) {
        ESP_LOGE(TAG, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

    ESP_LOGW(TAG, "quic init ok");

    return 0;
}


static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
    struct addrinfo hints = {};
    struct addrinfo *res, *rp;
    int rv;
    int fd = -1;

    hints.ai_flags = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        ESP_LOGE(TAG, "getaddrinfo: %i", rv);
        // fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            ESP_LOGE(TAG, "unable to create socket");
            continue;
        }
        break;
    }

    if (fd == -1) {
        ESP_LOGE(TAG, "fd = -1");
        freeaddrinfo(res);
        return fd;
    }

    *paddrlen = rp->ai_addrlen;
    memcpy(addr, rp->ai_addr, rp->ai_addrlen);

    ESP_LOGW(TAG, "create_sock ok, fd=%i", fd);

    return fd;
}


static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen,
                        int fd, const struct sockaddr *remote_addr,
                        size_t remote_addrlen) {
    socklen_t len;

    if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
        ESP_LOGE(TAG, "connect: %s\n", strerror(errno));
        return -1;
    }

    len = *plocal_addrlen;

    if (getsockname(fd, local_addr, &len) == -1) {
        ESP_LOGE(TAG, "getsockname: %s\n", strerror(errno));
        return -1;
    }

    *plocal_addrlen = len;

    ESP_LOGW(TAG, "connect_sock ok");

    return 0;
}

static int numeric_host_family(const char *hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

// const char * crypto_default_ciphers =  
//     "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_"
//     "SHA256:TLS_AES_128_CCM_SHA256";


// const char *crypto_default_groups = "X25519:P-256:P-384:P-521";

static int numeric_host(const char *hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

static int client_ssl_init(struct client *c, const char * host, const char * port) {
  c->ssl_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
  if (!c->ssl_ctx) {
    ESP_LOGE(TAG,"wolfSSL_CTX_new: %s", wolfSSL_ERR_error_string(wolfSSL_ERR_get_error(), NULL));
    return -1;
  }


  if (ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx) != 0) {
    ESP_LOGE(TAG, "ngtcp2_crypto_wolfssl_configure_client_context failed");
    return -1;
  }

    wolfSSL_CTX_set_verify(c->ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);

  c->ssl = SSL_new(c->ssl_ctx);
  if (!c->ssl) {
    ESP_LOGE(TAG, "SSL_new: %s, %08x\n", ERR_error_string(ERR_get_error(), NULL), (int)c->ssl);
    return -1;
  }

  SSL_set_app_data(c->ssl, &c->conn_ref);
  SSL_set_connect_state(c->ssl);
  SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, strlen(ALPN));
  if (!numeric_host(host)) {
    SSL_set_tlsext_host_name(c->ssl, host);
  }

  /* For NGTCP2_PROTO_VER_V1 */
  SSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters);

  ESP_LOGW(TAG, "client_ssl_init OK");

  return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct client *c = (struct client *)conn_ref->user_data;
  return c->conn;
}



int QuicClient::read(struct client *c) {
    uint8_t rx_buf[1280] = {0};
    // static uint8_t * rx_buf;
    // rx_buf = (uint8_t *)heap_caps_malloc(1280, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    // memset(rx_buf, 0, 1280);

    struct sockaddr_storage addr;
    struct iovec iov = {rx_buf, sizeof(rx_buf)};
    struct msghdr msg = {};
    ssize_t nread;
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {};
    int rv;

    msg.msg_name = &addr;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        msg.msg_namelen = sizeof(addr);

        nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);


        if (nread == -1) {
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                ESP_LOGE(TAG, "recvmsg: %s\n", strerror(errno));
            }
            break;
        }

        ESP_LOGD(TAG, "recv %zi", nread);

        path.local.addrlen = c->local_addrlen;
        path.local.addr = (struct sockaddr *)&c->local_addr;
        path.remote.addrlen = msg.msg_namelen;
        path.remote.addr = (ngtcp2_sockaddr*)msg.msg_name;

        rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, rx_buf, (size_t)nread,
                                timestamp());
        if (rv != 0) {
            ESP_LOGE(TAG, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
            if (!c->last_error.error_code) {
                if (rv == NGTCP2_ERR_CRYPTO) {
                    ngtcp2_ccerr_set_tls_alert(&c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
                }
                else {
                    ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
                }
            }
            // free(rx_buf);
            return rv;
        }
    }
    // free(rx_buf);
    return 0;
}


int client_send_packet(struct client *c, uint8_t *data, size_t datalen) {
  struct iovec iov = {(uint8_t *)data, datalen};
  struct msghdr msg = {};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    ESP_LOGE(TAG, "sendmsg: %s", strerror(errno));

    return -1;
  }
  ESP_LOGD(TAG, "sent %zi", nwrite);

  return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;

  return 0;
}



static int client_write_streams(struct client *c) {
    uint8_t tx_buf[1280] = {0};
    // static uint8_t * tx_buf;
    // tx_buf = (uint8_t *)heap_caps_malloc(1280, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    // memset(tx_buf, 0, 1280);

    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite;
    
    ngtcp2_path_storage ps;
    ngtcp2_vec datav;
    size_t datavcnt;
    int64_t stream_id;
    ngtcp2_ssize wdatalen;
    uint32_t flags;
    int fin;

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

        flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (fin) {
        //   flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }

        nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, tx_buf, sizeof(tx_buf),
                                        &wdatalen, flags, stream_id, &datav,
                                        datavcnt, ts);
        if (nwrite < 0) {
        switch (nwrite) {
        case NGTCP2_ERR_WRITE_MORE:
            c->stream.nwrite += (size_t)wdatalen;
            continue;
        default:
            ESP_LOGE(TAG, "ngtcp2_conn_writev_stream: %s\n",
                    ngtcp2_strerror((int)nwrite));
            ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
            // free(tx_buf);
            return -1;
        }
        }

        if (nwrite == 0) {
            // free(tx_buf);
            return 0;
        }

        if (wdatalen > 0) {
        c->stream.nwrite += (size_t)wdatalen;
        }

        if (client_send_packet(c, tx_buf, (size_t)nwrite)) {
            ESP_LOGE(TAG, "error sending packet");
            break;
        }
    }

    // free(tx_buf);
    return 0;
}


int QuicClient::write(struct client *c) {
    ngtcp2_tstamp expiry, now;

    

    if (client_write_streams(c) != 0) {
        return -1;
    }

    expiry = ngtcp2_conn_get_expiry(c->conn);
    now = timestamp();

    uint64_t t = expiry < now ? 1 : ((expiry - now) / NGTCP2_SECONDS * 1000);

    c->timer_repeat = t;

    return 0;
}


int QuicClient::init(struct client *c, StreamBufferHandle_t rx_s_buf, const char * host, const char * port) {
    quic_rx_streambuf = rx_s_buf;
    

    struct sockaddr_storage remote_addr, local_addr;
    socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);
    
    memset(c, 0, sizeof(*c));

    ngtcp2_ccerr_default(&c->last_error);

    c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                        host, port);
    if (c->fd == -1) {
        ESP_LOGE(TAG, "failed");
        return -1;
    }

    if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd,
                    (struct sockaddr *)&remote_addr, remote_addrlen) != 0) {
        ESP_LOGE(TAG, "failed");
        return -1;
    }

    memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
    c->local_addrlen = local_addrlen;

    if (client_ssl_init(c, host, port) != 0) {
        ESP_LOGE(TAG, "ssl init failed");
        return -1;
    }

    if (client_quic_init(c, 
                        (struct sockaddr *)&remote_addr, 
                        remote_addrlen,
                        (struct sockaddr *)&local_addr, 
                        local_addrlen) != 0) 
    {
        ESP_LOGE(TAG, "quic init failed");
        return -1;
    }

    c->stream.stream_id = -1;
    c->conn_ref.get_conn = get_conn;
    c->conn_ref.user_data = c;

    ESP_LOGW(TAG, "client_init ok");
    return 0;
}


void QuicClient::close(struct client *c) {
    ESP_LOGW(TAG, "client_close");
    ngtcp2_ssize nwrite;
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    uint8_t buf[1280];

    if (ngtcp2_conn_in_closing_period(c->conn) ||
        ngtcp2_conn_in_draining_period(c->conn)) {
        return;
    }

    ngtcp2_path_storage_zero(&ps);

    nwrite = ngtcp2_conn_write_connection_close(
        c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
    if (nwrite < 0) {
        fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
                ngtcp2_strerror((int)nwrite));
        return;
    }

    client_send_packet(c, buf, (size_t)nwrite);
}


int client_handle_expiry(struct client *c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    ESP_LOGE(TAG, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;    
  }

  return 0;
}


void QuicClient::clean(struct client *c) {
    SSL_clear(c->ssl);
}
