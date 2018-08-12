#include "assert.h"
#include "mbedtls/md5.h"
#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/utils/hex_utils.h"
#include "crypto_stream.h"
#include "crypto_cipher_ctx_i.h"
#include "crypto_ppbloom.h"

#define SODIUM_BLOCK_SIZE   64

static int crypto_cipher_key_size(crypto_cipher_t cipher);
static int crypto_cipher_nonce_size(crypto_cipher_t cipher);
static crypto_cipher_kt_t crypto_stream_get_cipher_type(crypto_processor_t processor, crypto_method_t method);
static int crypto_stream_cipher_ctx_init(crypto_processor_t processor, crypto_cipher_ctx_data_t ctx, crypto_method_t method, uint8_t is_encode);
static int crypto_cipher_ctx_set_nonce(
    crypto_processor_t process, crypto_cipher_ctx_data_t cipher_ctx, uint8_t *nonce, size_t nonce_len, uint8_t is_encode);
static unsigned char * crypto_md5(crypto_processor_t process, const unsigned char *d, size_t n, unsigned char *md);
static int crypto_stream_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *n, uint64_t ic, const uint8_t *k, crypto_method_t method);

crypto_cipher_t crypto_chipper_stream_create(
    crypto_processor_t processor,
    const char * pass, const char * key, crypto_method_t method)
{
    crypto_cipher_t cipher = mem_alloc(processor->m_alloc, sizeof(struct crypto_cipher));

    bzero(cipher, sizeof(*cipher));

    cipher->method = method;
        
    if (method == crypto_method_stream_salsa20
        || method == crypto_method_stream_chacha20
        || method == crypto_method_stream_chacha20_ietf)
    {
        crypto_cipher_kt_t cipher_info = mem_alloc(processor->m_alloc, sizeof(crypto_cipher_kt));
        cipher->info             = cipher_info;
        cipher->info->base       = NULL;
        /* cipher->info->key_bitlen = supported_stream_ciphers_key_size[method] * 8; */
        /* cipher->info->iv_size    = supported_stream_ciphers_nonce_size[method]; */
    }
    else {
        cipher->info = crypto_stream_get_cipher_type(processor, method);
    }

    if (cipher->info == NULL && cipher->key_len == 0) {
        CPE_ERROR(processor->m_em, "Cipher %s not found in crypto library", crypto_method_name(method));
        crypto_cipher_free(processor, cipher);
        return NULL;
    }

    if (key != NULL) {
        cipher->key_len = crypto_parse_key(processor, key, cipher->key, crypto_cipher_key_size(cipher));
    }
    else {
        cipher->key_len = crypto_derive_key(processor, pass, cipher->key, crypto_cipher_key_size(cipher));
    }

    if (cipher->key_len == 0) {
        CPE_ERROR(processor->m_em, "Cannot generate key and NONCE");
        crypto_cipher_free(processor, cipher);
        return NULL;
    }
    
    if (method == crypto_method_stream_rc4_md5) {
        cipher->nonce_len = 16;
    }
    else {
        cipher->nonce_len = crypto_cipher_nonce_size(cipher);
    }

    return cipher;
}

static int crypto_cipher_nonce_size(crypto_cipher_t cipher) {
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->iv_size;
}

static int crypto_cipher_key_size(crypto_cipher_t cipher) {
    /*
     * Semi-API changes (technically public, morally prnonceate)
     * Renamed a few headers to include _internal in the name. Those headers are
     * not supposed to be included by users.
     * Changed md_info_t into an opaque structure (use md_get_xxx() accessors).
     * Changed pk_info_t into an opaque structure.
     * Changed cipher_base_t into an opaque structure.
     */
    if (cipher == NULL) {
        return 0;
    }
    /* From Version 1.2.7 released 2013-04-13 Default Blowfish keysize is now 128-bits */
    return cipher->info->key_bitlen / 8;
}

static crypto_cipher_kt_t
crypto_stream_get_cipher_type(crypto_processor_t processor, crypto_method_t method) {
    switch(method) {
    case crypto_method_stream_rc4:
    case crypto_method_stream_rc4_md5:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("ARC4-128");
    case crypto_method_stream_aes_128_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("AES-128-CFB128");
    case crypto_method_stream_aes_192_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("AES-192-CFB128");
    case crypto_method_stream_aes_256_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("AES-256-CFB128");
    case crypto_method_stream_aes_128_ctr:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("AES-128-CTR");
    case crypto_method_stream_aes_192_ctr:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("AES-192-CTR");
    case crypto_method_stream_aes_256_ctr:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("AES-256-CTR");
    case crypto_method_stream_bf_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("BLOWFISH-CFB64");
    case crypto_method_stream_camellia_128_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("CAMELLIA-128-CFB128");
    case crypto_method_stream_camellia_192_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("CAMELLIA-192-CFB128");
    case crypto_method_stream_camellia_256_cfb:
        return (crypto_cipher_kt_t)mbedtls_cipher_info_from_string("CAMELLIA-256-CFB128");
    default:
        CPE_ERROR(processor->m_em, "Cipher %s currently is not supported by mbed TLS library", crypto_method_name(method));
        return NULL;
    }
}

int crypto_stream_encrypt_all(crypto_processor_t processor, write_stream_t ws, void const * plaintext, uint32_t plaintext_size) {
    crypto_cipher_t cipher = processor->m_cipher;
    int totall_len = 0;
    int once_len;
    
    struct crypto_cipher_ctx_data cipher_ctx;
    if (crypto_stream_ctx_init(processor, &cipher_ctx, 1) != 0) return -1;

    size_t nonce_len = cipher->nonce_len;
    uint8_t *nonce = cipher_ctx.nonce;
    if (crypto_cipher_ctx_set_nonce(processor, &cipher_ctx, nonce, nonce_len, 1) != 0) {
        crypto_stream_ctx_fini(processor, &cipher_ctx);
        return -1;
    }
    once_len = stream_write(ws, nonce, nonce_len);
    if (once_len != nonce_len) {
        return -1;
    }

    mem_buffer_t data_buffer = &processor->m_data_buffer;
    mem_buffer_clear_data(data_buffer);

    void * ciphertext = mem_buffer_alloc(data_buffer, plaintext_size);
    size_t ciphertext_size = plaintext_size;
    
    int err = 0;
    if (cipher->method >= crypto_method_stream_salsa20) {
        err = crypto_stream_xor_ic(
            (uint8_t *)ciphertext,
            (const uint8_t *)plaintext, (uint64_t)(plaintext_size),
            (const uint8_t *)nonce, 0, cipher->key, cipher->method);
    }
    else {
        err = mbedtls_cipher_update(
            cipher_ctx.evp,
            (const uint8_t *)plaintext, (size_t)plaintext_size,
            (uint8_t *)ciphertext, &ciphertext_size);
    }
    
    crypto_stream_ctx_fini(processor, &cipher_ctx);

    if (err) {
        return -1;
    }

    if (processor->m_debug >= 2) {
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "PLAIN: %s", cpe_hex_dup_buf(plaintext, plaintext_size, &processor->m_tmp_buffer));
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "CIPHER: %s", cpe_hex_dup_buf(ciphertext, ciphertext_size, &processor->m_tmp_buffer));
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "NONCE: %s", cpe_hex_dup_buf(nonce, nonce_len, &processor->m_tmp_buffer));
    }

    once_len = stream_write(ws, ciphertext, ciphertext_size);
    if (once_len != ciphertext_size) {
        return -1;
    }
    totall_len += once_len;
    
    return totall_len;
}

int crypto_stream_encrypt(
    crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx,
    write_stream_t ws, void const * plaintext, uint32_t plaintext_size)
{
    crypto_cipher_t cipher = processor->m_cipher;

    int totall_len = 0;
    int once_len;

    assert(plaintext);
    assert(plaintext_size);
    
    if (!cipher_ctx->init) {
        crypto_cipher_ctx_set_nonce(processor, cipher_ctx, cipher_ctx->nonce, cipher->nonce_len, 1);

        once_len = stream_write(ws, cipher_ctx->nonce, cipher->nonce_len);
        if (once_len != cipher->nonce_len) {
            CPE_ERROR(
                processor->m_em, "crypto: %s: encrypt: write nonce fail, size=%d",
                crypto_method_name(processor->m_cipher->method), (int)cipher->nonce_len);
            return -1;
        }
        totall_len += once_len;
        
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;
    }

    mem_buffer_clear_data(&processor->m_data_buffer);
    
    void * ciphertext;
    size_t ciphertext_size;

    if (cipher->method >= crypto_method_stream_salsa20) {
        int padding = cipher_ctx->counter % SODIUM_BLOCK_SIZE;

        ciphertext_size = plaintext_size;
        ciphertext = mem_buffer_alloc(&processor->m_data_buffer, (padding + plaintext_size) * 2);

        void const * input_buf = plaintext;
        size_t input_size = plaintext_size;
        
        if (padding) {
            input_size += padding;

            mem_buffer_clear_data(&processor->m_tmp_buffer);
            input_buf = mem_buffer_alloc(&processor->m_tmp_buffer, input_size);

            sodium_memzero((void*)input_buf, padding);
            memcpy(((char*)input_buf) + padding, plaintext, plaintext_size);
        }
        
        crypto_stream_xor_ic((uint8_t *)ciphertext,
                             (const uint8_t *)input_buf, (uint64_t)input_size,
                             (const uint8_t *)cipher_ctx->nonce, cipher_ctx->counter / SODIUM_BLOCK_SIZE,
                             cipher->key, cipher->method);

        cipher_ctx->counter += plaintext_size;

        if (padding) {
            memmove(ciphertext, ciphertext + padding, ciphertext_size);
        }
    }
    else {
        ciphertext_size = plaintext_size;
        ciphertext = mem_buffer_alloc(&processor->m_data_buffer, ciphertext_size);

        if (mbedtls_cipher_update(
                cipher_ctx->evp,
                (const uint8_t *)plaintext, plaintext_size,
                (uint8_t *)ciphertext, &ciphertext_size) != 0)
        {
            CPE_ERROR(
                processor->m_em, "crypto: %s: encrypt: cipher update fail, len = %d!",
                crypto_method_name(processor->m_cipher->method), plaintext_size);
            return -1;
        }
    }

    if (processor->m_debug >= 2) {
        CPE_INFO(processor->m_em, "PLAIN: %s", cpe_hex_dup_buf(plaintext, plaintext_size, &processor->m_tmp_buffer));
        CPE_INFO(processor->m_em, "CIPHER: %s", cpe_hex_dup_buf(ciphertext, ciphertext_size, &processor->m_tmp_buffer));
    }

    once_len = stream_write(ws, ciphertext, ciphertext_size);
    if (once_len != ciphertext_size) {
        CPE_ERROR(
            processor->m_em, "crypto: %s: encrypt: write fail, size=%d",
            crypto_method_name(processor->m_cipher->method),
            (int)ciphertext_size);
        return -1;
    }
    totall_len += once_len;
    
    return totall_len;
}

int crypto_stream_decrypt_all(
    crypto_processor_t processor, write_stream_t ws, void const * ciphertext, uint32_t ciphertext_size)
{
    crypto_cipher_t cipher = processor->m_cipher;

    if (ciphertext_size <= cipher->nonce_len) return -1;
    
    struct crypto_cipher_ctx_data cipher_ctx;
    if (crypto_stream_ctx_init(processor, &cipher_ctx, 0) != 0) return -1;

    memcpy(cipher_ctx.nonce, ciphertext, cipher->nonce_len);
    
    mem_buffer_clear_data(&processor->m_data_buffer);
    size_t plaintext_size = ciphertext_size - cipher->nonce_len;
    void * plaintext = mem_buffer_alloc(&processor->m_data_buffer, plaintext_size);
        
    if (processor->m_ppbloom && crypto_ppbloom_check(processor->m_ppbloom, cipher_ctx.nonce, (int)cipher->nonce_len) == 1) {
        CPE_ERROR(processor->m_em, "crypto: stream: repeat IV detected");
        return -1;
    }

    crypto_cipher_ctx_set_nonce(processor, &cipher_ctx, cipher_ctx.nonce, cipher->nonce_len, 0);

    int err = 0;
    if (cipher->method >= crypto_method_stream_salsa20) {
        err = crypto_stream_xor_ic(
            (uint8_t *)plaintext,
            (const uint8_t *)(ciphertext) + cipher->nonce_len, (uint64_t)(ciphertext_size - cipher->nonce_len),
            (const uint8_t *)cipher_ctx.nonce, 0, cipher->key, cipher->method);
    }
    else {
        err = mbedtls_cipher_update(
            cipher_ctx.evp,
            (const uint8_t *)ciphertext, (size_t)ciphertext_size,
            (uint8_t *)plaintext, &plaintext_size);
    }

    crypto_stream_ctx_fini(processor, &cipher_ctx);

    if (err) {
        return -1;
    }

    if (processor->m_debug >= 2) {
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "PLAIN: %s", cpe_hex_dup_buf(plaintext, plaintext_size, &processor->m_tmp_buffer));
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "CIPHER: %s", cpe_hex_dup_buf(ciphertext, ciphertext_size, &processor->m_tmp_buffer));
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "NONCE: %s", cpe_hex_dup_buf(cipher_ctx.nonce, cipher->nonce_len, &processor->m_tmp_buffer));
    }

    if (processor->m_ppbloom) {
        crypto_ppbloom_add(processor->m_ppbloom, (void *)cipher_ctx.nonce, (int)cipher->nonce_len);
    }

    int len = stream_write(ws, plaintext, plaintext_size);
    if (len != plaintext_size) {
        return -1;
    }

    return len;
}

int crypto_stream_decrypt(
    crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, write_stream_t ws, void const * ciphertext, uint32_t ciphertext_size)
{
    crypto_cipher_t cipher = processor->m_cipher;

    /* static buffer_t tmp = { 0, 0, 0, NULL }; */

    /* int err = CRYPTO_OK; */

    /* brealloc(&tmp, ciphertext->len, capacity); */
    /* buffer_t *plaintext = &tmp; */
    /* plaintext->len = ciphertext->len; */

    if (!cipher_ctx->init) {
        if (cipher_ctx->chunk_size + ciphertext_size < cipher->nonce_len) {
            if (cipher_ctx->chunk == NULL) {
                assert(cipher_ctx->chunk_size == 0);
                assert(cipher_ctx->chunk_capacity == 0);

                cipher_ctx->chunk = mem_alloc(processor->m_alloc, cipher->nonce_len);
                cipher_ctx->chunk_capacity = cipher->nonce_len;
            }

            assert(cipher_ctx->chunk_capacity == cipher->nonce_len);
            memcpy(((char*)cipher_ctx->chunk) + cipher_ctx->chunk_size, ciphertext, ciphertext_size);
            cipher_ctx->chunk_size += ciphertext_size;
            return 0;
        }

        /* uint8_t * nonce   = cipher_ctx->nonce; */
        /* size_t nonce_len = cipher->nonce_len; */
        /* plaintext->len -= left_len; */

        uint16_t used_len;
        if (cipher_ctx->chunk_size) {
            assert(cipher->nonce_len > cipher_ctx->chunk_size);

            used_len = cipher->nonce_len - cipher_ctx->chunk_size;
            memcpy(cipher_ctx->nonce, cipher_ctx->chunk, cipher_ctx->chunk_size);
        }
        else {
            used_len = cipher->nonce_len;
        }
        memcpy(cipher_ctx->nonce + cipher_ctx->chunk_size, ciphertext, used_len);
        crypto_cipher_ctx_set_nonce(processor, cipher_ctx, cipher_ctx->nonce, cipher->nonce_len, 0);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;

        if (cipher->method >= crypto_method_stream_rc4_md5) {
            if (processor->m_ppbloom && crypto_ppbloom_check(processor->m_ppbloom, (void *)cipher_ctx->nonce, (int)cipher->nonce_len) == 1) {
                CPE_ERROR(processor->m_em, "crypto: stream: repeat IV detected");
                return -1;
            }
        }

        ciphertext += used_len;
        ciphertext_size -= used_len;
    }

    void * plaintext;
    size_t plaintext_size;
    
    int err = 0;
    if (cipher->method >= crypto_method_stream_salsa20) {
        int padding = cipher_ctx->counter % SODIUM_BLOCK_SIZE;

        plaintext_size = ciphertext_size;
        plaintext = mem_buffer_alloc(&processor->m_data_buffer, (padding + ciphertext_size) * 2);

        void const * input_buf = ciphertext;
        size_t input_size = ciphertext_size;
        
        if (padding) {
            input_size += padding;

            mem_buffer_clear_data(&processor->m_tmp_buffer);
            input_buf = mem_buffer_alloc(&processor->m_tmp_buffer, input_size);

            sodium_memzero((void*)input_buf, padding);
            memcpy(((char*)input_buf) + padding, ciphertext, ciphertext_size);
        }
        
        crypto_stream_xor_ic(
            (uint8_t *)plaintext,
            (const uint8_t *)input_buf, (uint64_t)input_size,
            (const uint8_t *)cipher_ctx->nonce,
            cipher_ctx->counter / SODIUM_BLOCK_SIZE,
            cipher->key, cipher->method);

        cipher_ctx->counter += ciphertext_size;

        if (padding) {
            memmove(plaintext, plaintext + padding, plaintext_size);
        }
    }
    else {
        plaintext_size = ciphertext_size;
        plaintext = mem_buffer_alloc(&processor->m_data_buffer, ciphertext_size);
        
        err = mbedtls_cipher_update(
            cipher_ctx->evp,
            (const uint8_t *)ciphertext, (size_t)ciphertext_size,
            (uint8_t *)plaintext, &plaintext_size);
    }

    if (err) {
        return -1;
    }

    if (processor->m_debug >= 2) {
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "PLAIN: %s", cpe_hex_dup_buf(plaintext, plaintext_size, &processor->m_tmp_buffer));
        mem_buffer_clear_data(&processor->m_tmp_buffer);
        CPE_INFO(processor->m_em, "CIPHER: %s", cpe_hex_dup_buf(ciphertext, ciphertext_size, &processor->m_tmp_buffer));
    }

    // Add to bloom filter
    if (cipher_ctx->init == 1) {
        if (cipher->method >= crypto_method_stream_rc4_md5) {
            if (processor->m_ppbloom) {
                if (processor->m_ppbloom && crypto_ppbloom_check(processor->m_ppbloom, (void *)cipher_ctx->nonce, (int)cipher->nonce_len) == 1) {
                    CPE_ERROR(processor->m_em, "crypto: stream: repeat IV detected");
                    return -1;
                }
                crypto_ppbloom_add(processor->m_ppbloom, (void *)cipher_ctx->nonce, (int)cipher->nonce_len);
            }
            cipher_ctx->init = 2;
        }
    }

    int len = stream_write(ws, plaintext, plaintext_size);
    if (len != plaintext_size) {
        return -1;
    }

    return 0;
}

int crypto_stream_ctx_init(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx, uint8_t is_encode) {
    sodium_memzero(cipher_ctx, sizeof(*cipher_ctx));
    if (crypto_stream_cipher_ctx_init(processor, cipher_ctx, processor->m_cipher->method, is_encode) != 0) return -1;

    if (is_encode) {
        randombytes_buf(cipher_ctx->nonce, processor->m_cipher->nonce_len);
    }

    return 0;
}

int crypto_stream_cipher_ctx_init(crypto_processor_t processor, crypto_cipher_ctx_data_t ctx, crypto_method_t method, uint8_t is_encode) {
    assert(method >= crypto_method_stream_min && method <= crypto_method_stream_max);
    assert(method != crypto_method_stream_salsa20);
    assert(ctx->init == 0);
    
    const char * ciphername = crypto_method_name(method);
    crypto_cipher_kt_t cipher = crypto_stream_get_cipher_type(processor, method);
    if (cipher == NULL) {
        CPE_ERROR(processor->m_em, "Cipher %s not found in mbed TLS library", ciphername);
        return -1;
    }

    ctx->evp = mem_alloc(processor->m_alloc, sizeof(crypto_cipher_evp));
    bzero(ctx->evp, sizeof(crypto_cipher_evp));
    
    crypto_cipher_evp_t evp = ctx->evp;

    mbedtls_cipher_init(evp);
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        mem_free(processor->m_alloc, ctx->evp);
        CPE_ERROR(processor->m_em, "Cannot initialize mbed TLS cipher context");
        return -1;
    }

    return 0;
}

void crypto_stream_ctx_fini(crypto_processor_t processor, crypto_cipher_ctx_data_t cipher_ctx) {
    if (cipher_ctx->chunk != NULL) {
        mem_free(processor->m_alloc, cipher_ctx->chunk);
        cipher_ctx->chunk = NULL;
    }

    if (cipher_ctx->evp) {
        mbedtls_cipher_free(cipher_ctx->evp);
        mem_free(processor->m_alloc, cipher_ctx->evp);
    }
}

static int crypto_stream_xor_ic(
    uint8_t *c, const uint8_t *m, uint64_t mlen,
    const uint8_t *n, uint64_t ic, const uint8_t *k,
    crypto_method_t method)
{
    switch (method) {
    case crypto_method_stream_salsa20:
        return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
    case crypto_method_stream_chacha20:
        return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
    case crypto_method_stream_chacha20_ietf:
        return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, (uint32_t)ic, k);
    default:
        return 0;
    }
}

static int crypto_cipher_ctx_set_nonce(
    crypto_processor_t process, crypto_cipher_ctx_data_t cipher_ctx, uint8_t *nonce, size_t nonce_len, uint8_t is_encode)
{
    const unsigned char *true_key;

    crypto_cipher_t cipher = process->m_cipher;

    if (nonce == NULL) {
        CPE_ERROR(process->m_em, "cipher_ctx_set_nonce(): NONCE is null");
        return -1;
    }

    if (cipher->method >= crypto_method_stream_salsa20) {
        return 0;
    }

    if (cipher->method == crypto_method_stream_rc4_md5) {
        unsigned char key_nonce[32];
        memcpy(key_nonce, cipher->key, 16);
        memcpy(key_nonce + 16, nonce, 16);
        true_key  = crypto_md5(process, key_nonce, 32, NULL);
        nonce_len = 0;
    }
    else {
        true_key = cipher->key;
    }

    crypto_cipher_evp_t evp = cipher_ctx->evp;
    if (evp == NULL) {
        CPE_INFO(process->m_em, "cipher_ctx_set_nonce(): Cipher context is null");
        return -1;
    }
    
    if (mbedtls_cipher_setkey(evp, true_key, (int)(cipher->key_len * 8), is_encode ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0) {
        mbedtls_cipher_free(evp);
        CPE_ERROR(process->m_em, "Cannot set mbed TLS cipher key");
        return -1;
    }
    
    if (mbedtls_cipher_set_iv(evp, nonce, nonce_len) != 0) {
        mbedtls_cipher_free(evp);
        CPE_ERROR(process->m_em, "Cannot set mbed TLS cipher NONCE");
        return -1;
    }

    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        CPE_ERROR(process->m_em, "Cannot finalize mbed TLS cipher context");
        return -1;
    }

    if (process->m_debug) {
        mem_buffer_clear_data(&process->m_tmp_buffer);
        CPE_INFO(process->m_em, "NONCE: %s", cpe_hex_dup_buf(nonce, nonce_len, &process->m_tmp_buffer));
        mem_buffer_clear_data(&process->m_tmp_buffer);
        CPE_INFO(process->m_em, "KEY: %s", cpe_hex_dup_buf(true_key, 32, &process->m_tmp_buffer));
    }
    
    return 0;
}

static unsigned char *
crypto_md5(crypto_processor_t process, const unsigned char *d, size_t n, unsigned char *md) {
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }

    if (mbedtls_md5_ret(d, n, md) != 0) {
        CPE_ERROR(process->m_em, "Failed to calculate MD5");
        return NULL;
    }

    return md;
}
