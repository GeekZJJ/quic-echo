/* SPDX-License-Identifier: MIT */

#include "config.h"

#include "connection.h"
#include "gnutls-glue.h"
#include "utils.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_SIZE 1280
#define MAX_STREAMS 10

typedef struct _Client
{
  Connection *connection;
  Stream *streams[MAX_STREAMS]; /* owned by connection */
  size_t n_streams;             /* how many streams we open */
  size_t stream_index;          /* the current stream index */
  size_t n_coalescing;          /* how many lines are coalesced into a
                                   single packet */
  size_t coalesce_count;        /* the number of lines currently coalesced */
} Client;

static void
client_deinit (Client *client)
{
  connection_free (client->connection);
}

static void
rand_cb (uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  int ret;

  ret = gnutls_rnd (GNUTLS_RND_RANDOM, dest, destlen);
  if (ret < 0)
    g_debug ("gnutls_rnd: %s\n", gnutls_strerror (ret));
}

static int
get_new_connection_id_cb (ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                          size_t cidlen, void *user_data)
{
  int ret;

  ret = gnutls_rnd (GNUTLS_RND_RANDOM, cid->data, cidlen);
  if (ret < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  cid->datalen = cidlen;
  return 0;
}

static int
acked_stream_data_offset_cb (ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen,
                             void *user_data, void *stream_user_data)
{
  Connection *connection = user_data;
  Stream *stream = connection_find_stream (connection, stream_id);
  if (stream)
    stream_mark_acked (stream, offset + datalen);
  return 0;
}

static int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data)
{
  g_debug ("receiving %zu bytes from stream #%zd", datalen, stream_id);
  write (STDOUT_FILENO, data, datalen);
  return 0;
}

static const ngtcp2_callbacks callbacks =
  {
    /* Use the default implementation from ngtcp2_crypto */
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
  };

static int
handle_stdin (Client *client)
{
  uint8_t buf[BUF_SIZE];
  size_t nread = 0;
  int ret;

  while (nread < sizeof(buf))
    {
      ret = read (STDIN_FILENO, buf + nread, sizeof(buf) - nread);
      if (ret == 0)
        {
          connection_close (client->connection, 0);
          return 0;
        }
      else if (ret < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
          g_message ("read: %s", g_strerror (errno));
          return -1;
        }
      else
        nread += ret;
    }
  if (nread == sizeof(buf))
    {
      g_message ("read buffer overflow");
      return -1;
    }

  if (!client->streams[client->stream_index])
    {
      ngtcp2_conn *conn = connection_get_ngtcp2_conn (client->connection);
      if (!ngtcp2_conn_get_streams_bidi_left (conn))
        {
          g_info ("no available bidi streams; skipping");
          return 0;
        }

      int64_t stream_id;

      ret = ngtcp2_conn_open_bidi_stream (conn, &stream_id, NULL);
      if (ret < 0)
        {
          g_message ("ngtcp2_conn_open_bidi_stream: %s",
                     ngtcp2_strerror (ret));
          return -1;
        }

      __attribute__((cleanup(stream_freep))) Stream *stream = NULL;

      stream = stream_new (stream_id);
      if (!stream)
        return -1;

      client->streams[client->stream_index] =
        g_steal_pointer (&stream);
      connection_add_stream (client->connection,
                             client->streams[client->stream_index]);

      g_debug ("opened stream #%zd", stream_id);
    }

  if (client->streams[client->stream_index])
    {
      ret = stream_push_data (client->streams[client->stream_index],
                              buf, nread);
      if (ret < 0)
        return -1;

      g_debug ("buffered %zd bytes", nread);

      if (++client->coalesce_count < client->n_coalescing)
        return 0;
    }

  ret = connection_write (client->connection);
  if (ret < 0)
    return -1;

  client->stream_index++;
  client->stream_index %= client->n_streams;
  client->coalesce_count = 0;

  return 0;
}

#define MAX_EVENTS 64

static int
run (Client *client)
{
  __attribute__((cleanup(closep))) int epoll_fd = -1;

  epoll_fd = epoll_create1 (0);
  if (epoll_fd < 0)
    {
      g_message ("epoll_create1: %s", g_strerror (errno));
      return -1;
    }

  int flags;

  flags = fcntl (STDIN_FILENO, F_GETFL, 0);
  if (flags < 0)
    {
      g_message ("fcntl: %s", g_strerror (errno));
      return -1;
    }
  flags = fcntl (STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
  if (flags < 0)
    {
      g_message ("fcntl: %s", g_strerror (errno));
      return -1;
    }

  struct epoll_event ev;

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = STDIN_FILENO;
  if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
    {
      g_message ("epoll_ctl: %s", g_strerror (errno));
      return -1;
    }

  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  ev.data.fd = connection_get_socket_fd (client->connection);
  if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
    {
      g_message ("epoll_ctl: %s", g_strerror (errno));
      return -1;
    }

  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = connection_get_timer_fd (client->connection);
  if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
    {
      g_message ("epoll_ctl: %s", g_strerror (errno));
      return -1;
    }

  for (;;)
    {
      struct epoll_event events[MAX_EVENTS];
      int nfds;

      nfds = epoll_wait (epoll_fd, events, MAX_EVENTS, -1);
      if (nfds < 0)
        {
          g_message ("epoll_wait: %s", g_strerror (errno));
          return -1;
        }

      for (int n = 0; n < nfds; n++)
        {
	  int ret;

          if (events[n].data.fd == connection_get_socket_fd (client->connection))
            {
              if (events[n].events & EPOLLIN)
                {
                  ret = connection_read (client->connection);
                  if (ret < 0)
                    return -1;
                }
              if (events[n].events & EPOLLOUT)
                {
                  ret = connection_write (client->connection);
                  if (ret < 0)
                    return -1;
                }
            }

          if (events[n].data.fd == connection_get_timer_fd (client->connection))
            {
              ngtcp2_conn *conn =
                connection_get_ngtcp2_conn (client->connection);

              ret = ngtcp2_conn_handle_expiry (conn, timestamp ());
              if (ret < 0)
                {
                  g_message ("ngtcp2_conn_handle_expiry: %s",
                             ngtcp2_strerror ((int)ret));
                  return -1;
                }

              ret = connection_write (client->connection);
              if (ret < 0)
                return -1;
            }

          if (events[n].data.fd == STDIN_FILENO)
            {
              ret = handle_stdin (client);
              if (ret < 0)
                return -1;
              if (connection_is_closed (client->connection))
                {
                  close (epoll_fd);
                  return 0;
                }
            }
        }
    }

  return 0;
}

static gint n_streams = 1;
static gint n_coalescing = 1;

static GOptionEntry entries[] =
  {
    { "streams", 's', 0, G_OPTION_ARG_INT, &n_streams,
      "Open M streams", "M" },
    { "coalescing", 'c', 0, G_OPTION_ARG_INT, &n_coalescing,
      "Coalesce input lines per N", "N" },
    { NULL }
  };

int
main (int argc, char **argv)
{
  __attribute__((cleanup(client_deinit))) Client client =
    {
      .connection = NULL,
      .streams = { NULL, },
      .n_streams = 0,
      .stream_index = 0,
      .n_coalescing = 0,
      .coalesce_count = 0,
    };
  int ret;

  g_set_prgname ("cli");

  g_autoptr(GOptionContext) context = NULL;
  context = g_option_context_new ("HOST PORT CA-CERTS - QUIC echo client");
  g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

  g_autoptr(GError) err = NULL;
  if (!g_option_context_parse (context, &argc, &argv, &err))
    {
      g_printerr ("option parsing failed: %s\n", err->message);
      return EXIT_FAILURE;
    }

  if (argc != 4)
    {
      g_autofree gchar *help =
        g_option_context_get_help (context, FALSE, NULL);
      g_printerr ("%s", help);
      return EXIT_FAILURE;
    }

  /* Create a client socket */
  struct sockaddr_storage local_addr, remote_addr;
  size_t local_addrlen = sizeof(local_addr), remote_addrlen;

  __attribute__((cleanup(closep))) int fd = -1;

  fd = resolve_and_connect (argv[1], argv[2],
                            (struct sockaddr *)&local_addr,
                            &local_addrlen,
                            (struct sockaddr *)&remote_addr,
                            &remote_addrlen);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "resolve_and_connect failed\n");

  /* Create a TLS client session */
  __attribute__((cleanup(gnutls_certificate_free_credentialsp)))
    gnutls_certificate_credentials_t cred = NULL;

  cred = create_tls_client_credentials (argv[3]);
  if (!cred)
    error (EXIT_FAILURE, EINVAL, "create_tls_client_credentials failed\n");

  __attribute__((cleanup(gnutls_deinitp))) gnutls_session_t session = NULL;

  session = create_tls_client_session (cred);
  if (!session)
    error (EXIT_FAILURE, EINVAL, "create_tls_client_session failed\n");

  /* Create an ngtcp2 client connection */
  ngtcp2_path path =
    {
      .local = {
        .addrlen = local_addrlen,
        .addr = (struct sockaddr *)&local_addr
      },
      .remote = {
        .addrlen = remote_addrlen,
        .addr = (struct sockaddr *)&remote_addr
      }
    };

  ngtcp2_settings settings;
  ngtcp2_settings_default (&settings);
  settings.initial_ts = timestamp ();
  settings.log_printf = log_printf;

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  ngtcp2_cid scid, dcid;
  if (get_random_cid (&scid) < 0 || get_random_cid (&dcid) < 0)
    error (EXIT_FAILURE, EINVAL, "get_random_cid failed\n");

  __attribute__((cleanup(connection_freep))) Connection *connection = NULL;

  connection = connection_new (g_steal_pointer (&session), steal_fd (&fd));
  if (!connection)
    error (EXIT_FAILURE, EINVAL, "connection_new failed\n");

  __attribute__((cleanup(ngtcp2_conn_delp))) ngtcp2_conn *conn = NULL;

  ret = ngtcp2_conn_client_new (&conn, &dcid, &scid, &path,
                                NGTCP2_PROTO_VER_V1,
                                &callbacks, &settings, &params, NULL,
                                connection);
  if (ret < 0)
    error (EXIT_FAILURE, EINVAL, "ngtcp2_conn_client_new: %s\n",
           ngtcp2_strerror (ret));

  connection_set_ngtcp2_conn (connection, g_steal_pointer (&conn));
  connection_set_local_addr (connection,
                             (struct sockaddr *)&local_addr, local_addrlen);
  connection_set_remote_addr (connection,
                             (struct sockaddr *)&remote_addr, remote_addrlen);

  ret = connection_start (connection);
  if (ret < 0)
    error (EXIT_FAILURE, EINVAL, "connection_start failed\n");

  client.connection = g_steal_pointer (&connection);
  client.n_streams = n_streams;
  client.n_coalescing = n_coalescing;
  client.coalesce_count = 0;

  return run (&client) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
