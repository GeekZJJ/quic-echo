/* SPDX-License-Identifier: MIT */

#ifndef CONNECTION_H_
#define CONNECTION_H_

#include "stream.h"
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <stdbool.h>

typedef struct _Connection Connection;

Connection *connection_new (gnutls_session_t session, int socket_fd);
void connection_free (Connection *connection);

ngtcp2_conn *connection_get_ngtcp2_conn (Connection *connection);
void connection_set_ngtcp2_conn (Connection *connection, ngtcp2_conn *conn);
int connection_get_socket_fd (Connection *connection);
void connection_set_socket_fd (Connection *connection, int socket_fd);
int connection_get_timer_fd (Connection *connection);
struct sockaddr *connection_get_local_addr (Connection *connection,
                                            size_t *local_addrlen);
void connection_set_local_addr (Connection *connection,
                                struct sockaddr *local_addr,
                                size_t local_addrlen);
void connection_set_remote_addr (Connection *connection,
                                 struct sockaddr *remote_addr,
                                 size_t remote_addrlen);

int connection_start (Connection *connection);
int connection_read (Connection *connection);
int connection_write (Connection *connection);
void connection_close (Connection *connection, uint64_t error_code);
bool connection_is_closed (Connection *connection);

void connection_add_stream (Connection *connection, Stream *stream);
Stream *connection_find_stream (Connection *connection, int64_t stream_id);

/* For __attribute__((cleanup)) */
static inline void
connection_freep (Connection **p)
{
  Connection *connection = *p;
  if (connection)
    connection_free (connection);
}

static inline void
ngtcp2_conn_delp (ngtcp2_conn **p)
{
  ngtcp2_conn *conn = *p;
  if (conn)
    ngtcp2_conn_del (conn);
}

#endif
