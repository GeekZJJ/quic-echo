#ifndef __PLAINTEXT_H
#define __PLAINTEXT_H

#include <ngtcp2/ngtcp2.h>

#define NGTCP2_INITIAL_AEAD_OVERHEAD 16
#define NGTCP2_FAKE_AEAD_OVERHEAD NGTCP2_INITIAL_AEAD_OVERHEAD
#define NGTCP2_FAKE_HP_MASK "\x00\x00\x00\x00\x00"

int null_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                        const uint8_t *plaintext, size_t plaintextlen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *aad, size_t aadlen);

int null_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                        const ngtcp2_crypto_aead_ctx *aead_ctx,
                        const uint8_t *ciphertext, size_t ciphertextlen,
                        const uint8_t *nonce, size_t noncelen,
                        const uint8_t *aad, size_t aadlen);

int null_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                        const ngtcp2_crypto_cipher_ctx *hp_ctx,
                        const uint8_t *sample);

int recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
                      void *user_data);

int update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                      ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                      ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                      const uint8_t *current_rx_secret,
                      const uint8_t *current_tx_secret, size_t secretlen,
                      void *user_data);

void delete_crypto_aead_ctx(ngtcp2_conn *conn,
                                   ngtcp2_crypto_aead_ctx *aead_ctx,
                                   void *user_data);

void delete_crypto_cipher_ctx(ngtcp2_conn *conn,
                                     ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                     void *user_data);

int get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data,
                                   void *user_data);

int client_initial(ngtcp2_conn *conn, void *user_data);

int recv_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid,
                               void *user_data);

int recv_crypto_data_client(ngtcp2_conn *conn,
                            ngtcp2_encryption_level encryption_level,
                            uint64_t offset, const uint8_t *data,
                            size_t datalen, void *user_data);

int recv_crypto_data_server(ngtcp2_conn *conn,
                                   ngtcp2_encryption_level encryption_level,
                                   uint64_t offset, const uint8_t *data,
                                   size_t datalen, void *user_data);

#endif
