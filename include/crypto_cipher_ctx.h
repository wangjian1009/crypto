#ifndef CRYPTO_CIPHER_CTX_H_INCLEDED
#define CRYPTO_CIPHER_CTX_H_INCLEDED
#include "crypto_types.h"

CRYPTO_BEGIN_DECL

crypto_cipher_ctx_t crypto_cipher_ctx_create(crypto_processor_t processor, uint8_t is_encode);
void crypto_cipher_ctx_free(crypto_cipher_ctx_t cipher_ctx);

CRYPTO_END_DECL

#endif
