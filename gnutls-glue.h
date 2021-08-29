/* SPDX-License-Identifier: MIT */

#ifndef GNUTLS_GLUE_H_
#define GNUTLS_GLUE_H_

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>

int setup_gnutls_for_quic (gnutls_session_t session, ngtcp2_conn *conn);

gnutls_certificate_credentials_t create_tls_client_credentials (const char *ca_file);
gnutls_session_t create_tls_client_session (gnutls_certificate_credentials_t cred);

gnutls_certificate_credentials_t create_tls_server_credentials (const char *key_file, const char *cert_file);
gnutls_session_t create_tls_server_session (gnutls_certificate_credentials_t cred);

static inline void
gnutls_certificate_free_credentialsp (gnutls_certificate_credentials_t *p)
{
  gnutls_certificate_credentials_t cred = *p;
  if (cred)
    gnutls_certificate_free_credentials (cred);
}

static inline void
gnutls_deinitp (gnutls_session_t *p)
{
  gnutls_session_t session = *p;
  if (session)
    gnutls_deinit (session);
}

#endif  /* GNUTLS_GLUE_H_ */
