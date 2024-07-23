#include "plaintext.h"
#include <assert.h>
#include <string.h>

static uint8_t null_secret[32];
static uint8_t null_iv[16];

int null_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                 const ngtcp2_crypto_aead_ctx *aead_ctx,
                 const uint8_t *plaintext, size_t plaintextlen,
                 const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                 size_t aadlen) {
    (void)dest;
    (void)aead;
    (void)aead_ctx;
    (void)plaintext;
    (void)plaintextlen;
    (void)nonce;
    (void)noncelen;
    (void)aad;
    (void)aadlen;
    if (plaintextlen && plaintext != dest) {
        memcpy(dest, plaintext, plaintextlen);
    }
    memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);
    return 0;
}

int null_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                 const ngtcp2_crypto_aead_ctx *aead_ctx,
                 const uint8_t *ciphertext, size_t ciphertextlen,
                 const uint8_t *nonce, size_t noncelen, const uint8_t *aad,
                 size_t aadlen) {
    (void)dest;
    (void)aead;
    (void)aead_ctx;
    (void)ciphertext;
    (void)nonce;
    (void)noncelen;
    (void)aad;
    (void)aadlen;
    assert(ciphertextlen >= NGTCP2_FAKE_AEAD_OVERHEAD);
    memmove(dest, ciphertext, ciphertextlen - NGTCP2_FAKE_AEAD_OVERHEAD);
    return 0;
}

int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                 const ngtcp2_crypto_cipher_ctx *hp_ctx,
                 const uint8_t *sample) {
    (void)hp;
    (void)hp_ctx;
    (void)sample;
    memcpy(dest, NGTCP2_FAKE_HP_MASK, sizeof(NGTCP2_FAKE_HP_MASK) - 1);
    return 0;
}

int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *user_data) {
    (void)conn;
    (void)hd;
    (void)user_data;
    return 0;
}

void init_crypto_ctx(ngtcp2_crypto_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD;
    ctx->max_encryption = 9999;
    ctx->max_decryption_failure = 8888;
}

void init_initial_crypto_ctx(ngtcp2_crypto_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->aead.max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD;
    ctx->max_encryption = 9999;
    ctx->max_decryption_failure = 8888;
}

int submit_crypto_data(ngtcp2_conn *conn,
                       ngtcp2_encryption_level encryption_level) {
    uint8_t buf[768];
    ngtcp2_ssize encoded_size = ngtcp2_transport_params_encode(
        buf, sizeof(buf), ngtcp2_conn_get_local_transport_params(conn));
    assert(encoded_size > 0);
    return ngtcp2_conn_submit_crypto_data(conn, encryption_level, buf,
                                          encoded_size);
}

int handle_crypto_data(ngtcp2_conn *conn, const uint8_t *data, size_t datalen) {
    return ngtcp2_conn_decode_and_set_remote_transport_params(conn, data,
                                                              datalen);
}

int install_0rtt_key(ngtcp2_conn *conn) {
    ngtcp2_crypto_ctx crypto_ctx;
    ngtcp2_crypto_aead_ctx aead_ctx = {0};
    ngtcp2_crypto_cipher_ctx hp_ctx = {0};
    init_initial_crypto_ctx(&crypto_ctx);
    ngtcp2_conn_set_initial_crypto_ctx(conn, &crypto_ctx);
    return ngtcp2_conn_install_initial_key(conn, &aead_ctx, null_iv, &hp_ctx,
                                           &aead_ctx, null_iv, &hp_ctx,
                                           sizeof(null_iv));
}

int install_1rtt_key(ngtcp2_conn *conn) {
    ngtcp2_crypto_aead_ctx aead_ctx = {0};
    ngtcp2_crypto_cipher_ctx hp_ctx = {0};
    assert(0 == ngtcp2_conn_install_rx_key(conn, null_secret,
                                           sizeof(null_secret), &aead_ctx,
                                           null_iv, sizeof(null_iv), &hp_ctx));
    assert(0 == ngtcp2_conn_install_tx_key(conn, null_secret,
                                           sizeof(null_secret), &aead_ctx,
                                           null_iv, sizeof(null_iv), &hp_ctx));
    return 0;
}

int install_handshake_key(ngtcp2_conn *conn) {
    ngtcp2_crypto_ctx crypto_ctx;
    ngtcp2_crypto_aead_ctx aead_ctx = {0};
    ngtcp2_crypto_cipher_ctx hp_ctx = {0};
    init_crypto_ctx(&crypto_ctx);
    ngtcp2_conn_set_crypto_ctx(conn, &crypto_ctx);
    assert(0 == ngtcp2_conn_install_rx_handshake_key(conn, &aead_ctx, null_iv,
                                                     sizeof(null_iv), &hp_ctx));
    assert(0 == ngtcp2_conn_install_tx_handshake_key(conn, &aead_ctx, null_iv,
                                                     sizeof(null_iv), &hp_ctx));
    return 0;
}

int client_initial(ngtcp2_conn *conn, void *user_data) {
    (void)user_data;
    assert(0 == install_0rtt_key(conn));
    assert(0 == submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL));

    return 0;
}

int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                        void *user_data) {
    (void)user_data;
    assert(0 == install_0rtt_key(conn));
    return 0;
}

int recv_crypto_data_server(ngtcp2_conn *conn,
                            ngtcp2_encryption_level encryption_level,
                            uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data) {
    (void)offset;
    (void)user_data;

    switch (encryption_level) {
        case NGTCP2_ENCRYPTION_LEVEL_INITIAL: {
            assert(0 == submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL));
            assert(0 == install_handshake_key(conn));
            assert(0 == handle_crypto_data(conn, data, datalen));
            assert(0 == submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE));
            assert(0 == install_1rtt_key(conn));
            return 0;
        }
        case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE: {
            submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_1RTT);
            ngtcp2_conn_tls_handshake_completed(conn);
            return 0;
        }
        default:
            return 0;
    }
    return 0;
}

int recv_crypto_data_client(ngtcp2_conn *conn,
                            ngtcp2_encryption_level encryption_level,
                            uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data) {
    (void)offset;
    (void)user_data;
    switch (encryption_level) {
        case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
            assert(0 == install_handshake_key(conn));
            return 0;
        case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
            if (ngtcp2_conn_get_handshake_completed(conn)) {
                return 0;
            }
            assert(0 == handle_crypto_data(conn, data, datalen));
            assert(0 == install_1rtt_key(conn));
            assert(0 == submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE));
            ngtcp2_conn_tls_handshake_completed(conn);
            return 0;
        default:
            return 0;
    }
    return 0;
}

int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
               ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
               ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
               const uint8_t *current_rx_secret,
               const uint8_t *current_tx_secret, size_t secretlen,
               void *user_data) {
    (void)conn;
    (void)current_rx_secret;
    (void)current_tx_secret;
    (void)user_data;
    (void)secretlen;

    assert(sizeof(null_secret) == secretlen);

    memset(rx_secret, 0xff, sizeof(null_secret));
    memset(tx_secret, 0xff, sizeof(null_secret));
    rx_aead_ctx->native_handle = NULL;
    memset(rx_iv, 0xff, sizeof(null_iv));
    tx_aead_ctx->native_handle = NULL;
    memset(tx_iv, 0xff, sizeof(null_iv));

    return 0;
}

void delete_crypto_aead_ctx(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *aead_ctx,
                            void *user_data) {
    (void)conn;
    (void)aead_ctx;
    (void)user_data;
}

void delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                              ngtcp2_crypto_cipher_ctx *cipher_ctx,
                              void *user_data) {
    (void)conn;
    (void)cipher_ctx;
    (void)user_data;
}

int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    memset(data, 0, NGTCP2_PATH_CHALLENGE_DATALEN);
    return 0;
}
