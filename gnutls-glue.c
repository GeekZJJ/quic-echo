/* SPDX-License-Identifier: MIT */

#include "config.h"

#include "gnutls-glue.h"

#include <glib.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#define PRIO "NORMAL:-VERS-ALL:+VERS-TLS1.3:" \
  "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:" \
  "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
  "%DISABLE_TLS13_COMPAT_MODE"

#define MAX_TP_SIZE 128

static int
handshake_secret_func (gnutls_session_t session,
                       gnutls_record_encryption_level_t glevel,
                       const void *secret_read, const void *secret_write,
                       size_t secret_size)
{
  ngtcp2_conn *conn = gnutls_session_get_ptr (session);
  ngtcp2_encryption_level level =
    ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level (glevel);
  uint8_t key[64], iv[64], hp_key[64];

  if (secret_read &&
      ngtcp2_crypto_derive_and_install_rx_key (conn,
                                               key, iv, hp_key, level,
                                               secret_read, secret_size) < 0)
    return -1;

  if (secret_write &&
      ngtcp2_crypto_derive_and_install_tx_key (conn,
                                               key, iv, hp_key, level,
                                               secret_write, secret_size) < 0)
    return -1;

  return 0;
}

static int
handshake_read_func (gnutls_session_t session,
                     gnutls_record_encryption_level_t glevel,
                     gnutls_handshake_description_t htype,
                     const void *data, size_t data_size)
{
  if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
    return 0;

  ngtcp2_conn *conn = gnutls_session_get_ptr (session);
  ngtcp2_encryption_level level =
    ngtcp2_crypto_gnutls_from_gnutls_record_encryption_level (glevel);

  int ret;

  ret = ngtcp2_conn_submit_crypto_data (conn, level, data, data_size);
  if (ret < 0)
    {
      g_debug ("ngtcp2_conn_submit_crypto_data: %s",
               ngtcp2_strerror (ret));
      return -1;
    }

  return 0;
}

static int
alert_read_func (gnutls_session_t session __attribute__((unused)),
                 gnutls_record_encryption_level_t level __attribute__((unused)),
                 gnutls_alert_level_t alert_level __attribute__((unused)),
                 gnutls_alert_description_t alert_desc __attribute__((unused)))
{
  return 0;
}

static int
tp_recv_func (gnutls_session_t session, const uint8_t *data, size_t data_size)
{
  ngtcp2_conn *conn = gnutls_session_get_ptr (session);
  int ret;

  ret = ngtcp2_conn_decode_and_set_remote_transport_params (conn, data, data_size);
  if (ret < 0)
    {
      g_message ("ngtcp2_conn_set_remote_transport_params: %s\n", ngtcp2_strerror (ret));
      return -1;
    }

  return 0;
}

static int
tp_send_func (gnutls_session_t session, gnutls_buffer_t extdata)
{
  ngtcp2_conn *conn = gnutls_session_get_ptr (session);

  const ngtcp2_transport_params *params = ngtcp2_conn_get_local_transport_params (conn);

  uint8_t buf[MAX_TP_SIZE];
  ngtcp2_ssize n_encoded =
    ngtcp2_transport_params_encode (buf, sizeof(buf), params);
  if (n_encoded < 0)
    {
      g_debug ("ngtcp2_transport_params_encode: %s", ngtcp2_strerror (n_encoded));
      return -1;
    }

  int ret = gnutls_buffer_append_data (extdata, buf, n_encoded);
  if (ret < 0)
    {
      g_debug ("gnutls_buffer_append_data failed: %s", gnutls_strerror (ret));
      return -1;
    }

  return n_encoded;
}

int
setup_gnutls_for_quic (gnutls_session_t session, ngtcp2_conn *conn)
{
  int ret;

  gnutls_handshake_set_secret_function (session, handshake_secret_func);
  gnutls_handshake_set_read_function (session, handshake_read_func);
  gnutls_alert_set_read_function (session, alert_read_func);

  ret = gnutls_session_ext_register (session, "QUIC Transport Parameters",
                                     NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS_V1,
                                     GNUTLS_EXT_TLS,
                                     tp_recv_func, tp_send_func,
                                     NULL, NULL, NULL,
                                     GNUTLS_EXT_FLAG_TLS |
                                     GNUTLS_EXT_FLAG_CLIENT_HELLO |
                                     GNUTLS_EXT_FLAG_EE);
  if (ret < 0)
    return ret;

  gnutls_datum_t alpn = { (unsigned char *)"h3", sizeof("h3")-1};
  gnutls_alpn_set_protocols(session, &alpn, 1, 0);

  gnutls_server_name_set (session, GNUTLS_NAME_DNS, "localhost",
                          sizeof("localhost")-1);

  ngtcp2_conn_set_tls_native_handle (conn, session);
  gnutls_session_set_ptr (session, conn);

  return 0;
}

gnutls_certificate_credentials_t
create_tls_client_credentials (const char *ca_file)
{
  __attribute__((cleanup(gnutls_certificate_free_credentialsp)))
    gnutls_certificate_credentials_t cred = NULL;
  int ret;

  ret = gnutls_certificate_allocate_credentials (&cred);
  if (ret < 0)
    {
      g_message ("gnutls_certificate_allocate_credentials: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  ret = gnutls_certificate_set_x509_trust_file (cred,
                                                ca_file,
                                                GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      g_message ("gnutls_certificate_set_x509_system_trust: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  return g_steal_pointer (&cred);
}

gnutls_session_t
create_tls_client_session (gnutls_certificate_credentials_t cred)
{
  __attribute__((cleanup(gnutls_deinitp)))
    gnutls_session_t session = NULL;
  int ret;

  ret = gnutls_init (&session,
                     GNUTLS_CLIENT |
                     GNUTLS_ENABLE_EARLY_DATA |
                     GNUTLS_NO_END_OF_EARLY_DATA);
  if (ret < 0)
    {
      g_message ("gnutls_init: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  ret = gnutls_priority_set_direct (session, PRIO, NULL);
  if (ret < 0)
    {
      g_message ("gnutls_priority_set_direct: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  ret = gnutls_credentials_set (session,
                                GNUTLS_CRD_CERTIFICATE,
                                cred);
  if (ret < 0)
    {
      g_message ("gnutls_credentials_set: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  return g_steal_pointer (&session);
}

gnutls_certificate_credentials_t
create_tls_server_credentials (const char *key_file, const char *cert_file)
{
  __attribute__((cleanup(gnutls_certificate_free_credentialsp)))
    gnutls_certificate_credentials_t cred = NULL;
  int ret;

  ret = gnutls_certificate_allocate_credentials (&cred);
  if (ret < 0)
    {
      g_message ("gnutls_certificate_allocate_credentials: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  ret = gnutls_certificate_set_x509_key_file (cred, cert_file, key_file,
                                              GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      g_message ("gnutls_certificate_set_x509_system_trust: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  return g_steal_pointer (&cred);
}

gnutls_session_t
create_tls_server_session (gnutls_certificate_credentials_t cred)
{
  __attribute__((cleanup(gnutls_deinitp)))
    gnutls_session_t session = NULL;
  int ret;

  ret = gnutls_init (&session,
                     GNUTLS_SERVER |
                     GNUTLS_ENABLE_EARLY_DATA |
                     GNUTLS_NO_END_OF_EARLY_DATA);
  if (ret < 0)
    {
      g_message ("gnutls_init: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  ret = gnutls_priority_set_direct (session, PRIO, NULL);
  if (ret < 0)
    {
      g_message ("gnutls_priority_set_direct: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  ret = gnutls_credentials_set (session,
                                GNUTLS_CRD_CERTIFICATE,
                                cred);
  if (ret < 0)
    {
      g_message ("gnutls_credentials_set: %s",
                  gnutls_strerror (ret));
      return NULL;
    }

  return g_steal_pointer (&session);
}
