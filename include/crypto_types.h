#ifndef CRYPTO_TYPES_H_INCLEDED
#define CRYPTO_TYPES_H_INCLEDED
#include "crypto_common.h"

CRYPTO_BEGIN_DECL

typedef enum crypto_method {
    crypto_method_none,
    crypto_method_stream_rc4,
    crypto_method_stream_rc4_md5,
    crypto_method_stream_aes_128_cfb,
    crypto_method_stream_aes_192_cfb,
    crypto_method_stream_aes_256_cfb,
    crypto_method_stream_aes_128_ctr,
    crypto_method_stream_aes_192_ctr,
    crypto_method_stream_aes_256_ctr,
    crypto_method_stream_bf_cfb,
    crypto_method_stream_camellia_128_cfb,
    crypto_method_stream_camellia_192_cfb,
    crypto_method_stream_camellia_256_cfb,
    crypto_method_stream_cast5_cfb,
    crypto_method_stream_des_cfb,
    crypto_method_stream_idea_cfb,
    crypto_method_stream_rc2_cfb,
    crypto_method_stream_seed_cfb,
    crypto_method_stream_salsa20,
    crypto_method_stream_chacha20,
    crypto_method_stream_chacha20_ietf,
    crypto_method_aes_128_gcm,
    crypto_method_aes_192_gcm,
    crypto_method_aes_256_gcm,
    crypto_method_chacha20_ietf_poly1305,
    crypto_method_xchacha20_ietf_poly1305,
    crypto_method_chiper_count
} crypto_method_t;

typedef struct crypto_processor * crypto_processor_t;
typedef struct crypto_cipher_ctx * crypto_cipher_ctx_t;

CRYPTO_END_DECL

#endif
