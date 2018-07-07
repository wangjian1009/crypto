#ifndef CRYPTO_PROCESSOR_H_INCLEDED
#define CRYPTO_PROCESSOR_H_INCLEDED
#include "cpe/utils/utils_types.h"
#include "crypto_types.h"

CRYPTO_BEGIN_DECL

crypto_processor_t crypto_processor_create(
    mem_allocrator_t alloc, error_monitor_t em, uint8_t debug,
    const char *password, const char *key, crypto_method_t method);

void crypto_processor_free(crypto_processor_t crypto_processor);

crypto_method_t crypto_processor_method(crypto_processor_t processor);

uint8_t crypto_processor_debug(crypto_processor_t processor);
void crypto_processor_set_debug(crypto_processor_t processor, uint8_t debug);

const char * crypto_method_name(crypto_method_t method);
crypto_method_t crypto_method_from_name(const char * method_name);

int crypto_encrypt_all(crypto_processor_t processor, write_stream_t ws, void const * data, size_t data_len);
int crypto_decrypt_all(crypto_processor_t processor, write_stream_t ws, void const * data, size_t data_len);

int crypto_encrypt(crypto_cipher_ctx_t cipher_ctx, write_stream_t ws, void const * data, size_t data_len);
int crypto_decrypt(crypto_cipher_ctx_t cipher_ctx, write_stream_t ws, void const * data, size_t data_len);
                   
CRYPTO_END_DECL

#endif
