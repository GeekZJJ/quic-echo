/* SPDX-License-Identifier: MIT */

#include "config.h"

#include "connection.h"

#include "gnutls-glue.h"
#include <sys/timerfd.h>
#include <unistd.h>
#include "utils.h"

#define BUF_SIZE 1280

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
  bool is_closed;
};

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

  return g_steal_pointer (&connection);
}

void
connection_free (Connection *connection)
{
  if (!connection)
    return;

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
        return -1;
    }

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

  if (!connection->streams)
    {
      ret = write_to_stream (connection, NULL);
      if (ret < 0)
        return -1;
    }
  else
    for (GList *l = connection->streams; l; l = l->next)
      {
	ret = write_to_stream (connection, l->data);
	if (ret < 0)
	  return -1;
      }

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
  if (expiry < now)
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
connection_close (Connection *connection, uint64_t error_code)
{
  ngtcp2_pkt_info pi;
  uint8_t buf[BUF_SIZE];

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);

  ngtcp2_ssize n_written;

  n_written = ngtcp2_conn_write_connection_close (connection->conn,
						  &ps.path, &pi,
						  buf, sizeof(buf),
						  error_code,
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
