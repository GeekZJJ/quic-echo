/* SPDX-License-Identifier: MIT */

#include "config.h"

#include "connection.h"

#include "gnutls-glue.h"
#include <sys/timerfd.h>
#include <unistd.h>
#include "utils.h"

#define BUF_SIZE 12800

struct _Connection
{
  gnutls_session_t session;
  ngtcp2_conn *conn;
  int socket_fd;
  int timer_fd;
  struct sockaddr_storage local_addr;
  size_t local_addrlen;
  struct sockaddr_storage remote_addr;
  size_t remote_addrlen;
  GList *streams;
  ngtcp2_map write_map;
  ngtcp2_map wait_map;
  bool is_closed;
};

datagram *new_datagram(uint64_t id, void *data, size_t datalen) {
    datagram *newdatagram = malloc(sizeof(datagram));
    if (!newdatagram) {
        g_error("malloc datagram failed");
        return NULL;
    }
    newdatagram->datalen = datalen;
    newdatagram->data = malloc(datalen);
    if (!newdatagram->data) {
        g_error("malloc datagram.data failed");
        free(newdatagram);
        return NULL;
    }
    memset(newdatagram->data, 0, newdatagram->datalen);
    memcpy(newdatagram->data, data, datalen);
    newdatagram->id = id;
    return newdatagram;
}

int free_datagram(void *data, void *) {
    datagram *datagram = data;
    free(datagram->data);
    free(datagram);
    return 0;
}

Connection *
connection_new (gnutls_session_t session,
                int socket_fd)
{
  __attribute__((cleanup(connection_freep)))
    Connection *connection = NULL;

  connection = g_new0 (Connection, 1);
  if (!connection)
    return NULL;

  connection->session = session;
  connection->socket_fd = socket_fd;
  connection->timer_fd = -1;

  ngtcp2_map_init(&connection->wait_map, ngtcp2_mem_default());
  ngtcp2_map_init(&connection->write_map, ngtcp2_mem_default());

  return g_steal_pointer (&connection);
}

void
connection_free (Connection *connection)
{
  if (!connection)
    return;

  ngtcp2_map_each_free(&connection->wait_map, free_datagram, NULL);
  ngtcp2_map_each_free(&connection->write_map, free_datagram, NULL);

  ngtcp2_map_free(&connection->wait_map);
  ngtcp2_map_free(&connection->write_map);

  if (connection->session)
    gnutls_deinit (connection->session);
  if (connection->conn)
    ngtcp2_conn_del (connection->conn);
  if (connection->socket_fd >= 0)
    close (connection->socket_fd);
  if (connection->timer_fd >= 0)
    close (connection->timer_fd);
  g_list_free_full (connection->streams, (GDestroyNotify)stream_free);
  g_free (connection);
}

void
connection_add_stream (Connection *connection, Stream *stream)
{
  connection->streams = g_list_append (connection->streams, stream);
}

Stream *
connection_find_stream (Connection *connection, int64_t stream_id)
{
  for (GList *l = connection->streams; l; l = l->next)
    {
      Stream *stream = l->data;
      if (stream_get_id (stream) == stream_id)
        return stream;
    }
  return NULL;
}

ngtcp2_map *
connection_get_waitmap (Connection *connection) {
    return &connection->wait_map;
}

ngtcp2_map *
connection_get_writemap (Connection *connection) {
    return &connection->write_map;
}

ngtcp2_conn *
connection_get_ngtcp2_conn (Connection *connection)
{
  return connection->conn;
}

void
connection_set_ngtcp2_conn (Connection *connection, ngtcp2_conn *conn)
{
  connection->conn = conn;
}

int
connection_get_socket_fd (Connection *connection)
{
  return connection->socket_fd;
}

void
connection_set_socket_fd (Connection *connection, int socket_fd)
{
  connection->socket_fd = socket_fd;
}

int
connection_get_timer_fd (Connection *connection)
{
  return connection->timer_fd;
}

struct sockaddr *
connection_get_local_addr (Connection *connection, size_t *local_addrlen)
{
  *local_addrlen = connection->local_addrlen;
  return (struct sockaddr *)&connection->local_addr;
}

void
connection_set_local_addr (Connection *connection,
                           struct sockaddr *local_addr,
                           size_t local_addrlen)
{
  memcpy (&connection->local_addr, local_addr, local_addrlen);
  connection->local_addrlen = local_addrlen;
}

void
connection_set_remote_addr (Connection *connection,
                           struct sockaddr *remote_addr,
                           size_t remote_addrlen)
{
  memcpy (&connection->remote_addr, remote_addr, remote_addrlen);
  connection->remote_addrlen = remote_addrlen;
}

int
connection_start (Connection *connection)
{
  g_return_val_if_fail (connection->session, -1);
  g_return_val_if_fail (connection->conn, -1);

  setup_gnutls_for_quic (connection->session, connection->conn);

  connection->timer_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (connection->timer_fd < 0)
    {
      g_message ("timerfd_create: %s", g_strerror (errno));
      return -1;
    }

  return 0;
}

int
connection_read (Connection *connection)
{
  uint8_t buf[BUF_SIZE];
  ngtcp2_ssize ret;

  for (;;)
    {
      struct sockaddr_storage remote_addr;
      size_t remote_addrlen = sizeof(remote_addr);
      ret = recv_packet (connection->socket_fd, buf, sizeof(buf),
                         (struct sockaddr *)&remote_addr, &remote_addrlen);
      if (ret < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
          g_message ("recv_packet: %s", g_strerror (errno));
          return -1;
        }

      ngtcp2_path path;
      memcpy (&path, ngtcp2_conn_get_path (connection->conn), sizeof(path));
      path.remote.addrlen = remote_addrlen;
      path.remote.addr = (struct sockaddr *)&remote_addr;

      ngtcp2_pkt_info pi;
      memset (&pi, 0, sizeof(pi));

      ret = ngtcp2_conn_read_pkt (connection->conn, &path, &pi, buf, ret,
                                  timestamp ());
      if (ret < 0)
	{
          g_message ("ngtcp2_conn_read_pkt: %s", ngtcp2_strerror (ret));
	  return -1;
	}
    }

  return 0;
}

void retrans_datagram(Connection *connection, datagram *data) {
    int n_accepted;
    uint64_t ts = timestamp();
    uint8_t buf[BUF_SIZE];
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_vec datav = {
        .base = NULL,
        .len = 0,
    };

    if (data) {
        datav.base = data->data;
        datav.len = data->datalen;
        g_message("retrans_datagram %lu", data->id);
    } else {
        g_info("retrans_datagram not exist in map");
        return;
    }

    ngtcp2_ssize n_written = ngtcp2_conn_writev_datagram(connection->conn, &ps.path, &pi,
                        buf, sizeof(buf),
                        &n_accepted,
                        0,
                        data->id,
                        &datav, 1,
                        ts);
    if (n_written <= 0) {
        g_message ("ngtcp2_conn_writev_stream: %s", ngtcp2_strerror ((int)n_written));
        ngtcp2_map_remove(connection_get_waitmap(connection), data->id);
        free_datagram(data, NULL);
        return;
    }

    int ret = send_packet (connection->socket_fd, buf, n_written,
                        (struct sockaddr *)&connection->remote_addr,
                        connection->remote_addrlen);
    if (ret < 0) {
        g_message ("send_packet: %s", strerror (errno));
        return;
    }
    g_message ("retrans send_packet: %ld", n_written);
}

typedef struct {
    void **values;
    size_t valueslen;
    size_t valuescap;
} iter_datagrams_context;

int iter_datagrams(void *data, void *ptr) {
    iter_datagrams_context *ctx = ptr;
    if (ctx->valueslen == ctx->valuescap) {
        size_t newcap = ctx->valuescap << 1;
        void *newvalues = realloc(ctx->values, newcap);
        if (newvalues == NULL) {
            g_message ("iter_datagrams: out of memory");
            return -ENOMEM;
        }
        ctx->values = newvalues;
        ctx->valuescap = newcap;
    }
    ctx->values[ctx->valueslen++] = data;
    return 0;
}

static int write_datagram (Connection *connection) {
    uint8_t buf[BUF_SIZE];

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi;
    uint64_t ts = timestamp ();

    uint32_t flags = NGTCP2_WRITE_DATAGRAM_FLAG_MORE;

    size_t key_size = ngtcp2_map_size(&connection->write_map);

    if (key_size == 0) {
        return 0;
    }

    iter_datagrams_context ictx = {
        .values = NULL,
        .valuescap = key_size,
        .valueslen = 0,
    };
    ictx.values = malloc(ictx.valuescap);

    ngtcp2_map_each(&connection->write_map, iter_datagrams, &ictx);

    for (int i = 0; i < key_size; i++) {
        datagram *datagram = ictx.values[i];
        int n_accepted;
        ngtcp2_vec datav = {
            .base = datagram->data,
            .len = datagram->datalen,
        };

        if ((i+1)==key_size) {
            flags &= ~NGTCP2_WRITE_DATAGRAM_FLAG_MORE;
        }

        ngtcp2_ssize n_written = ngtcp2_conn_writev_datagram(connection->conn, &ps.path, &pi,
                            buf, sizeof(buf),
                            &n_accepted,
                            flags,
                            datagram->id,
                            &datav, 1,
                            ts);
        if (n_written < 0) {
            if (n_written == NGTCP2_ERR_WRITE_MORE)
                continue;
            g_message ("ngtcp2_conn_writev_datagram: %s", ngtcp2_strerror ((int)n_written));
            break;
        }
        if (n_written == 0) {
            break;
        }
        if (n_accepted > 0) {
            ngtcp2_map_remove(&connection->write_map, datagram->id);
            ngtcp2_map_insert(&connection->wait_map, datagram->id, datagram);
        }

        int ret = send_packet (connection->socket_fd, buf, n_written,
                            (struct sockaddr *)&connection->remote_addr,
                            connection->remote_addrlen);
        if (ret < 0) {
            g_message ("send_packet: %s", strerror (errno));
            break;
        }
    }
    free(ictx.values);

  return 0;
}

static int
write_to_stream (Connection *connection, Stream *stream)
{
  uint8_t buf[BUF_SIZE];

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);

  ngtcp2_pkt_info pi;
  uint64_t ts = timestamp ();

  uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

  for (;;)
    {
      ngtcp2_vec datav;
      int64_t stream_id;

      if (stream)
        {
          datav.base = (void *)stream_peek_data (stream, &datav.len);
          if (datav.len == 0)
            {
              /* No stream data to be sent */
              stream_id = -1;
              flags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE;
            }
          else
            stream_id = stream_get_id (stream);
        }
      else
        {
          datav.base = NULL;
          datav.len = 0;
          stream_id = -1;
        }

      ngtcp2_ssize n_read, n_written;

      n_written = ngtcp2_conn_writev_stream (connection->conn, &ps.path, &pi,
					     buf, sizeof(buf),
					     &n_read,
					     flags,
					     stream_id,
					     &datav, 1,
					     ts);
      if (n_written < 0)
        {
          if (n_written == NGTCP2_ERR_WRITE_MORE)
            {
              stream_mark_sent (stream, n_read);
              continue;
            }
          g_message ("ngtcp2_conn_writev_stream: %s",
                     ngtcp2_strerror ((int)n_written));
          return -1;
        }

      if (n_written == 0)
        return 0;

      if (stream && n_read > 0)
        stream_mark_sent (stream, n_read);

      int ret;

      ret = send_packet (connection->socket_fd, buf, n_written,
                         (struct sockaddr *)&connection->remote_addr,
                         connection->remote_addrlen);
      if (ret < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
          g_message ("send_packet: %s", strerror (errno));
          return -1;
        }

      /* No stream data to be sent */
      if (stream && datav.len == 0)
        break;
    }

  return 0;
}

int
connection_write (Connection *connection)
{
  int ret;
  write_datagram(connection);
  write_to_stream(connection, NULL);

  ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry (connection->conn);
  ngtcp2_tstamp now = timestamp ();
  struct itimerspec it;
  memset (&it, 0, sizeof (it));

  ret = timerfd_settime (connection->timer_fd, 0, &it, NULL);
  if (ret < 0)
    {
      g_message ("timerfd_settime: %s", g_strerror (errno));
      return -1;
    }
  if (expiry <= now)
    {
      it.it_value.tv_sec = 0;
      it.it_value.tv_nsec = 1;
    }
  else
    {
      it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
      it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
    }
  ret = timerfd_settime (connection->timer_fd, 0, &it, NULL);
  if (ret < 0)
    {
      g_message ("timerfd_settime: %s", g_strerror (errno));
      return -1;
    }

  return 0;
}

void
connection_close (Connection *connection)
{
  ngtcp2_pkt_info pi;
  uint8_t buf[BUF_SIZE];

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);

  ngtcp2_ssize n_written;
  ngtcp2_ccerr ccerr;

  n_written = ngtcp2_conn_write_connection_close (connection->conn,
						  &ps.path, &pi,
						  buf, sizeof(buf),
						  &ccerr,
						  timestamp());
  if (n_written < 0)
    g_message ("ngtcp2_conn_write_connection_close: %s",
               ngtcp2_strerror ((int)n_written));
  else
    {
      ssize_t ret;

      ret = send_packet (connection->socket_fd, buf, (size_t)n_written,
                         (struct sockaddr *)&connection->remote_addr,
                         connection->remote_addrlen);
      if (ret < 0)
        g_message ("send_packet: %s", g_strerror (errno));
    }

  connection->is_closed = true;
}

bool
connection_is_closed (Connection *connection)
{
  return connection->is_closed;
}
