#ifndef _QUIC_CLIENT_H_
#define _QUIC_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "user_settings.h"  // DO NOT REMOVE
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#define KEY_BUF_SIZE   400


enum FrameType {
  FRAME_UNKNOWN = 0,
  FRAME_SUBSCRIPTION,
  FRAME_PUBLICATION,
  FRAME_SIGNAL
};

struct client {
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  ngtcp2_conn *conn;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
    bool write_in_progress;
  } stream;

  ngtcp2_ccerr last_error;

  uint32_t timer_repeat;
};


class QuicClient {
public:
    static int init(struct client *c, StreamBufferHandle_t rx_s_buf, const char * host, const char * port);
    static int write(struct client *c);
    static int read(struct client *c);
    static void close(struct client *c);
    static void clean(struct client *c);
};

// int client_init(struct client *c, StreamBufferHandle_t rx_s_buf, char * jwt, const char * host, const char * port);
// int client_write(struct client *c);
// int client_read(struct client *c);
// void client_close(struct client *c);
// void client_delete(struct client *c);

static int client_handle_expiry(struct client *c);
static int client_send_packet(struct client *c, uint8_t *data, size_t datalen);

#ifdef __cplusplus
}
#endif

#endif // _QUIC_CLIENT_H_
