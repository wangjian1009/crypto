#include "cpe/pal/pal_strings.h"
#include "crypto_cipher_ctx_i.h"

crypto_cipher_ctx_t
crypto_cipher_ctx_create(crypto_processor_t processor, uint8_t is_encode) {
    crypto_cipher_ctx_t cipher_ctx;

    cipher_ctx = mem_alloc(processor->m_alloc, sizeof(struct crypto_cipher_ctx));
    if (cipher_ctx == NULL) {
        CPE_ERROR(processor->m_em, "crypto: cipher_ctx alloc fail!");
        return NULL;
    }

    cipher_ctx->m_processor = processor;
    if (processor->ctx_init(processor, &cipher_ctx->m_data, is_encode) != 0) {
        CPE_ERROR(processor->m_em, "crypto: cipher_ctx alloc fail!");
        mem_free(processor->m_alloc, cipher_ctx);
        return NULL;
    }
    
    return cipher_ctx;
}

void crypto_cipher_ctx_free(crypto_cipher_ctx_t cipher_ctx) {
    crypto_processor_t processor = cipher_ctx->m_processor;
    processor->ctx_fini(processor, &cipher_ctx->m_data);
    mem_free(processor->m_alloc, cipher_ctx);
}

