#ifndef CRYPTO_STREAM_H_INCLEDED
#define CRYPTO_STREAM_H_INCLEDED
#include "crypto_processor_i.h"
#include "crypto_cipher.h"

CRYPTO_BEGIN_DECL

#define crypto_method_stream_min crypto_method_stream_rc4
#define crypto_method_stream_max crypto_method_stream_chacha20_ietf

crypto_cipher_t crypto_chipper_stream_create(
    crypto_processor_t processor,
    const char * password, const char * key, crypto_method_t method);

int crypto_stream_encrypt_all(crypto_processor_t processor, write_stream_t ws, void const * data, uint32_t data_size);
int crypto_stream_decrypt_all(crypto_processor_t processor, write_stream_t ws, void const * data, uint32_t data_size);
int crypto_stream_encrypt(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, write_stream_t ws, void const * data, uint32_t data_size);
int crypto_stream_decrypt(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, write_stream_t ws, void const * data, uint32_t data_size);

int crypto_stream_ctx_init(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, uint8_t is_encode);
void crypto_stream_ctx_fini(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx);

CRYPTO_END_DECL

#endif
