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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_SIZE 1280

typedef struct _Server
{
  int epoll_fd;
  int socket_fd;
  struct sockaddr_storage local_addr;
  size_t local_addrlen;
  /* list of Connection; TODO: use a hash table */
  GList *connections;
  gnutls_certificate_credentials_t cred;
  ngtcp2_settings settings;
  ngtcp2_cid scid;
} Server;

static inline void
server_deinit (Server *server)
{
  if (server->epoll_fd >= 0)
    close (server->epoll_fd);
  if (server->socket_fd >= 0)
    close (server->socket_fd);
  g_list_free_full (server->connections, (GDestroyNotify)connection_free);
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
stream_open_cb (ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  Connection *connection = user_data;
  __attribute__((cleanup(stream_freep))) Stream *stream = NULL;

  stream = stream_new (stream_id);
  connection_add_stream (connection, g_steal_pointer (&stream));
  return 0;
}

static int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data)
{
  Connection *connection = user_data;
  Stream *stream = connection_find_stream (connection, stream_id);

  if (stream)
    stream_push_data (stream, data, datalen);

  return 0;
}

static const ngtcp2_callbacks callbacks =
  {
    /* Use the default implementation from ngtcp2_crypto */
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
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
    .stream_open = stream_open_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
  };

static Connection *
find_connection (Server *server, const uint8_t *dcid, size_t dcid_size)
{
  for (GList *l = server->connections; l; l = l->next)
    {
      Connection *connection = l->data;
      ngtcp2_conn *conn = connection_get_ngtcp2_conn (connection);
      size_t n_scids = ngtcp2_conn_get_num_scid (conn);
      g_autofree ngtcp2_cid *scids = NULL;

      scids = g_new (ngtcp2_cid, n_scids);
      if (!scids)
        return NULL;

      n_scids = ngtcp2_conn_get_scid (conn, scids);
      for (size_t i = 0; i < n_scids; i++)
        {
          if (dcid_size == scids[i].datalen &&
              memcmp (dcid, scids[i].data, dcid_size) == 0)
              return connection;
        }
    }
  return NULL;
}

static Connection *
accept_connection (Server *server,
                   struct sockaddr *remote_addr, size_t remote_addrlen,
                   const uint8_t *data, size_t data_size)
{
  ngtcp2_pkt_hd header;
  int ret;

  ret = ngtcp2_accept (&header, data, data_size);
  if (ret < 0)
    return NULL;

  __attribute__((cleanup(gnutls_deinitp))) gnutls_session_t session = NULL;

  session = create_tls_server_session (server->cred);
  if (!session)
    return NULL;

  __attribute__((cleanup(connection_freep))) Connection *connection = NULL;

  connection = connection_new (g_steal_pointer (&session), server->socket_fd);
  if (!connection)
    return NULL;

  ngtcp2_path path =
    {
      .local = {
        .addrlen = server->local_addrlen,
        .addr = (struct sockaddr *)&server->local_addr
      },
      .remote = {
        .addrlen = remote_addrlen,
        .addr = (struct sockaddr *)remote_addr
      }
    };

  __attribute__((cleanup(ngtcp2_conn_delp))) ngtcp2_conn *conn = NULL;

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_streams_bidi = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_stream_data_bidi_remote = 128 * 1024;
  params.initial_max_data = 1024 * 1024;
  memcpy (&params.original_dcid, &header.dcid, sizeof (params.original_dcid));

  ngtcp2_cid scid;
  if (get_random_cid (&scid) < 0)
    return NULL;

  ret = ngtcp2_conn_server_new (&conn,
                                &header.scid,
                                &scid,
                                &path,
                                header.version,
                                &callbacks,
                                &server->settings,
                                &params,
                                NULL,
                                connection);
  if (ret < 0)
    {
      g_debug ("ngtcp2_conn_server_new: %s",
               ngtcp2_strerror (ret));
      return NULL;
    }

  connection_set_ngtcp2_conn (connection, g_steal_pointer (&conn));
  connection_set_local_addr (connection,
                             (struct sockaddr *)&server->local_addr,
                             server->local_addrlen);
  connection_set_remote_addr (connection,
                              (struct sockaddr *)remote_addr,
                              remote_addrlen);

  Connection *c = g_steal_pointer (&connection);
  server->connections = g_list_append (server->connections, c);
  return c;
}

static int
handle_incoming (Server *server)
{
  uint8_t buf[BUF_SIZE];

  for (;;)
    {
      ssize_t nread;
      struct sockaddr_storage remote_addr;
      size_t remote_addrlen = sizeof(remote_addr);
      int ret;

      nread = recv_packet (server->socket_fd, buf, sizeof(buf),
                           (struct sockaddr *)&remote_addr,
                           &remote_addrlen);
      if (nread < 0)
        {
          if (nread != EAGAIN && nread != EWOULDBLOCK)
            return 0;
          g_message ("recv_packet: %s\n", g_strerror (errno));
          return -1;
        }

      uint32_t version;
      const uint8_t *dcid, *scid;
      size_t dcidlen, scidlen;

      ret = ngtcp2_pkt_decode_version_cid (&version,
                                           &dcid, &dcidlen,
                                           &scid, &scidlen,
                                           buf, nread,
                                           NGTCP2_MAX_CIDLEN);
      if (ret < 0)
        {
          g_message ("ngtcp2_pkt_decode_version_cid: %s",
                     ngtcp2_strerror (ret));
          return -1;
        }

      /* Find any existing connection by DCID */
      Connection *connection = find_connection (server, dcid, dcidlen);
      if (!connection)
        {
          connection = accept_connection (server,
                                          (struct sockaddr *)&remote_addr,
                                          remote_addrlen,
                                          buf, nread);
          if (!connection)
            return -1;

          ret = connection_start (connection);
          if (ret < 0)
            return -1;

          struct epoll_event ev;
          ev.events = EPOLLIN | EPOLLET;
          ev.data.fd = connection_get_timer_fd (connection);
          ret = epoll_ctl (server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
          if (ret < 0)
            {
              g_message ("epoll_ctl: %s", g_strerror (ret));
              return -1;
            }
        }

      ngtcp2_conn *conn = connection_get_ngtcp2_conn (connection);

      ngtcp2_path path;
      memcpy (&path, ngtcp2_conn_get_path (conn), sizeof(path));
      path.remote.addrlen = remote_addrlen;
      path.remote.addr = (struct sockaddr *)&remote_addr;

      ngtcp2_pkt_info pi;
      memset (&pi, 0, sizeof(pi));

      ret = ngtcp2_conn_read_pkt (conn, &path, &pi, buf, nread, timestamp ());
      if (ret < 0)
        {
          g_message ("ngtcp2_conn_read_pkt: %s",
                     ngtcp2_strerror (ret));

          /* Remove the connection upon read error */
          GList *link =
            g_list_find (server->connections, connection);
          server->connections =
            g_list_remove_link (server->connections, link);
          ret = epoll_ctl (server->epoll_fd, EPOLL_CTL_DEL,
                           connection_get_timer_fd (connection),
                           NULL);
          if (ret < 0)
            {
              g_message ("epoll_ctl: %s",
                         g_strerror (errno));
              return -1;
            }
          connection_set_socket_fd (connection, -1);
          connection_free (connection);
        }
    }
}

#define MAX_EVENTS 64

static int
run (Server *server)
{
  __attribute__((cleanup(stream_freep))) Stream *stream = NULL;

  server->epoll_fd = epoll_create1 (0);
  if (server->epoll_fd < 0)
    {
      g_message ("epoll_create1: %s", g_strerror (errno));
      return -1;
    }

  struct epoll_event ev;

  ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
  ev.data.fd = server->socket_fd;
  if (epoll_ctl (server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
    {
      g_debug ("epoll_ctl: %s", g_strerror (errno));
      return -1;
    }

  for (;;)
    {
      struct epoll_event events[MAX_EVENTS];
      int nfds;

      nfds = epoll_wait (server->epoll_fd, events, MAX_EVENTS, -1);
      if (nfds < 0)
        {
          g_debug ("epoll_wait: %s", g_strerror (errno));
          return -1;
        }

      for (int n = 0; n < nfds; n++)
        {
	  int ret;

          if (events[n].data.fd == server->socket_fd)
            {
              if (events[n].events & EPOLLIN)
                (void)handle_incoming (server);

              if (events[n].events & EPOLLOUT)
		for (GList *l = server->connections; l; l = l->next)
		  {
		    Connection *connection = l->data;
		    (void)connection_write (connection);
		  }
            }
	  else
	    for (GList *l = server->connections; l; l = l->next)
	      {
		Connection *connection = l->data;
		if (events[n].data.fd == connection_get_timer_fd (connection))
		  {
		    ngtcp2_conn *conn =
		      connection_get_ngtcp2_conn (connection);
		    ret = ngtcp2_conn_handle_expiry (conn, timestamp ());
		    if (ret < 0)
		      {
			g_debug ("ngtcp2_conn_handle_expiry: %s",
				 ngtcp2_strerror (ret));
			continue;
		      }

		    (void)connection_write (connection);
		  }
	      }
        }
    }

  return 0;
}

static GOptionEntry entries[] =
  {
    { NULL }
  };

int
main (int argc, char **argv)
{
  __attribute__((cleanup(server_deinit))) Server server =
    {
      .connections = NULL,
      .cred = NULL,
      .local_addrlen = sizeof(struct sockaddr_storage),
      .epoll_fd = -1,
    };

  g_set_prgname ("serv");

  g_autoptr(GOptionContext) context = NULL;
  context = g_option_context_new ("HOST PORT KEY CERT - QUIC echo server");
  g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);

  g_autoptr(GError) err = NULL;
  if (!g_option_context_parse (context, &argc, &argv, &err))
    {
      g_printerr ("option parsing failed: %s\n", err->message);
      return EXIT_FAILURE;
    }

  if (argc != 5)
    {
      g_autofree gchar *help =
        g_option_context_get_help (context, FALSE, NULL);
      g_printerr ("%s", help);
      return EXIT_FAILURE;
    }

  /* Create a server socket */
  __attribute__((cleanup(closep))) int fd = -1;

  fd = resolve_and_bind (argv[1], argv[2],
                         (struct sockaddr *)&server.local_addr,
                         &server.local_addrlen);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "resolve_and_bind");
  server.socket_fd = steal_fd (&fd);

  /* Create a TLS server credentials */
  __attribute__((cleanup(gnutls_certificate_free_credentialsp)))
    gnutls_certificate_credentials_t cred = NULL;

  cred = create_tls_server_credentials (argv[3], argv[4]);
  if (!cred)
    error (EXIT_FAILURE, EINVAL, "create_tls_credentials");
  server.cred = g_steal_pointer (&cred);

  ngtcp2_settings_default (&server.settings);
  server.settings.initial_ts = timestamp ();
  server.settings.log_printf = log_printf;

  return run (&server) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
