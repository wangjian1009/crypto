#ifndef CRYPTO_CIPHER_CTX_I_H_INCLEDED
#define CRYPTO_CIPHER_CTX_I_H_INCLEDED
#include "crypto_cipher_ctx.h"
#include "crypto_processor_i.h"

CRYPTO_BEGIN_DECL

struct crypto_cipher_ctx_data {
    uint8_t init;
    uint64_t counter;
    crypto_cipher_evp_t evp;
    void * chunk;
    uint16_t chunk_size;
    uint16_t chunk_capacity;
    uint8_t salt[MAX_KEY_LENGTH];
    uint8_t skey[MAX_KEY_LENGTH];
    uint8_t nonce[MAX_NONCE_LENGTH];
};

struct crypto_cipher_ctx {
    crypto_processor_t m_processor;
    struct crypto_cipher_ctx_data m_data;
};

CRYPTO_END_DECL

#endif
