#ifndef CRYPTO_CHIPER_H_INCLEDED
#define CRYPTO_CHIPER_H_INCLEDED
#include "crypto_processor_i.h"

CRYPTO_BEGIN_DECL

struct crypto_cipher {
    crypto_method_t method;
    int skey;
    crypto_cipher_kt_t info;
    size_t nonce_len;
    size_t key_len;
    size_t tag_len;
    uint8_t key[MAX_KEY_LENGTH];
};

void crypto_cipher_free(crypto_processor_t processor, crypto_cipher_t cipher);

CRYPTO_END_DECL

#endif
