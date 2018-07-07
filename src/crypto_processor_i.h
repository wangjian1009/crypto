#ifndef CRYPTO_PROCESSOR_I_H_INCLEDED
#define CRYPTO_PROCESSOR_I_H_INCLEDED
#include "sodium.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md.h"
#include "cpe/pal/pal_queue.h"
#include "cpe/utils/memory.h"
#include "cpe/utils/error.h"
#include "cpe/utils/buffer.h"
#include "crypto_processor.h"

CRYPTO_BEGIN_DECL

#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH 32
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

typedef mbedtls_cipher_info_t crypto_cipher_kt, * crypto_cipher_kt_t;
typedef mbedtls_cipher_context_t crypto_cipher_evp, * crypto_cipher_evp_t;
typedef mbedtls_md_info_t crypto_digest_type, * crypto_digest_type_t;

typedef struct crypto_cipher * crypto_cipher_t;
typedef struct crypto_cipher_ctx_data * crypto_cipher_ctx_data_t;
typedef struct crypto_ppbloom * crypto_ppbloom_t;

struct crypto_processor {
    mem_allocrator_t m_alloc;
    error_monitor_t m_em;
    uint8_t m_debug;
    struct mem_buffer m_data_buffer;
    struct mem_buffer m_tmp_buffer;
    crypto_ppbloom_t m_ppbloom;

    crypto_cipher_t m_cipher;
    int(*encrypt_all)(crypto_processor_t processor, write_stream_t ws, void const * data, uint32_t data_size);
    int(*decrypt_all)(crypto_processor_t processor, write_stream_t ws, void const * data, uint32_t data_size);
    int(*encrypt)(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, write_stream_t ws, void const * data, uint32_t data_size);
    int(*decrypt)(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, write_stream_t ws, void const * data, uint32_t data_size);

    int (*ctx_init)(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, uint8_t is_enc);
    void (*ctx_fini)(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx);
};

int crypto_parse_key(crypto_processor_t processor, const char *base64, uint8_t *key, size_t key_len);
int crypto_derive_key(crypto_processor_t processor, const char *pass, uint8_t *key, size_t key_len);

CRYPTO_END_DECL

#endif

