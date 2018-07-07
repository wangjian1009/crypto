#include "cpe/pal/pal_string.h"
#include "cpe/pal/pal_strings.h"
#include "cpe/pal/pal_stdio.h"
#include "cpe/utils/base64.h"
#include "cpe/utils/stream_mem.h"
#include "cpe/utils/stream_buffer.h"
#include "cpe/utils/hex_utils.h"
#include "crypto_processor_i.h"
#include "crypto_cipher.h"
#include "crypto_cipher_ctx_i.h"
#include "crypto_stream.h"
#include "crypto_ppbloom.h"

static void crypto_processor_entropy_check(error_monitor_t em);

crypto_processor_t
crypto_processor_create(
    mem_allocrator_t alloc, error_monitor_t em, uint8_t debug,
    const char *password, const char *key, crypto_method_t method)
{
    crypto_processor_t processor;

    crypto_processor_entropy_check(em);

    if (sodium_init() == -1) {
        CPE_ERROR(em, "crypto_processor: Failed to initialize sodium");
        return NULL;
    }
    
    processor = mem_alloc(alloc, sizeof(struct crypto_processor));
    if (processor == NULL) {
        CPE_ERROR(em, "crypto_processor: alloc fail!");
        return NULL;
    }
    bzero(processor, sizeof(*processor));
    
    processor->m_alloc = alloc;
    processor->m_em = em;
    processor->m_debug = debug;
    processor->m_ppbloom = NULL;
    mem_buffer_init(&processor->m_data_buffer, alloc);
    mem_buffer_init(&processor->m_tmp_buffer, alloc);

    if (method >= crypto_method_stream_min && method <= crypto_method_stream_max) {
        processor->m_cipher = crypto_chipper_stream_create(processor, password, key, method);
        if (processor->m_cipher == NULL) goto CREATE_ERROR; 

        processor->encrypt_all = crypto_stream_encrypt_all;
        processor->decrypt_all = crypto_stream_decrypt_all;
        processor->encrypt     = crypto_stream_encrypt;
        processor->decrypt     = crypto_stream_decrypt;
        processor->ctx_init    = crypto_stream_ctx_init;
        processor->ctx_fini = crypto_stream_ctx_fini;
        return processor;
    }
    
    /*     for (i = 0; i < AEAD_CIPHER_NUM; i++) */
    /*         if (strcmp(method, supported_aead_ciphers[i]) == 0) { */
    /*             m = i; */
    /*             break; */
    /*         } */
    /*     if (m != -1) { */
    /*         cipher_t *cipher = aead_init(password, key, method); */
    /*         if (cipher == NULL) */
    /*             return NULL; */
    /*         crypto_t *crypto = (crypto_t *)ss_malloc(sizeof(crypto_t)); */
    /*         crypto_t tmp     = { */
    /*             .cipher      = cipher, */
    /*             .encrypt_all = &aead_encrypt_all, */
    /*             .decrypt_all = &aead_decrypt_all, */
    /*             .encrypt     = &aead_encrypt, */
    /*             .decrypt     = &aead_decrypt, */
    /*             .ctx_init    = &aead_ctx_init, */
    /*             .ctx_release = &aead_ctx_release, */
    /*         }; */
    /*         memcpy(crypto, &tmp, sizeof(crypto_t)); */
    /*         return crypto; */
    /*     } */

    CPE_ERROR(em, "crypto_processor: not support method %d!", method);
    
CREATE_ERROR:
    if (processor->m_cipher) {
        crypto_cipher_free(processor, processor->m_cipher);
        processor->m_cipher = NULL;
    }
    
    mem_buffer_clear(&processor->m_tmp_buffer);
    mem_free(alloc, processor);

    return NULL;
}

void crypto_processor_free(crypto_processor_t processor) {
    if (processor->m_ppbloom) {
        crypto_ppbloom_free(processor->m_ppbloom);
        processor->m_ppbloom = NULL;
    }

    if (processor->m_cipher) {
        crypto_cipher_free(processor, processor->m_cipher);
        processor->m_cipher = NULL;
    }
    
    mem_buffer_clear(&processor->m_data_buffer);
    mem_buffer_clear(&processor->m_tmp_buffer);
    mem_free(processor->m_alloc, processor);
}

crypto_method_t crypto_processor_method(crypto_processor_t processor) {
    return processor->m_cipher->method;
}

uint8_t crypto_processor_debug(crypto_processor_t processor) {
    return processor->m_debug;
}

void crypto_processor_set_debug(crypto_processor_t processor, uint8_t debug) {
    processor->m_debug = debug;
}

int crypto_encrypt_all(crypto_processor_t processor, write_stream_t ws, void const * data, size_t data_len) {
    return processor->encrypt_all(processor, ws, data, data_len);
}

int crypto_decrypt_all(crypto_processor_t processor, write_stream_t ws, void const * data, size_t data_len) {
    return processor->decrypt_all(processor, ws, data, data_len);
}

int crypto_encrypt(crypto_cipher_ctx_t cipher_ctx, write_stream_t ws, void const * data, size_t data_len) {
    return cipher_ctx->m_processor->encrypt(cipher_ctx->m_processor, &cipher_ctx->m_data, ws, data, data_len);
}

int crypto_decrypt(crypto_cipher_ctx_t cipher_ctx, write_stream_t ws, void const * data, size_t data_len) {
    return cipher_ctx->m_processor->decrypt(cipher_ctx->m_processor, &cipher_ctx->m_data, ws, data, data_len);
}

static void crypto_processor_entropy_check(error_monitor_t em) {
/* #if defined(__linux__) && defined(HAVE_LINUX_RANDOM_H) && defined(RNDGETENTCNT) */
/*     int fd; */
/*     int c; */

/*     if ((fd = open("/dev/random", O_RDONLY)) != -1) { */
/*         if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) { */
/*             LOGI("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n" */
/*                  "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n" */
/*                  "On virtualized Linux environments, also consider using virtio-rng.\n" */
/*                  "The service will not start until enough entropy has been collected.\n"); */
/*         } */
/*         close(fd); */
/*     } */
/* #endif */
}

int crypto_parse_key(crypto_processor_t processor, const char *base64, uint8_t *key, size_t key_len) {
    size_t base64_len = strlen(base64);

    /*尝试解码 */
    mem_buffer_clear_data(&processor->m_tmp_buffer);
    
    struct read_stream_mem is = CPE_READ_STREAM_MEM_INITIALIZER(base64, base64_len);
    struct write_stream_buffer ws = CPE_WRITE_STREAM_BUFFER_INITIALIZER(&processor->m_tmp_buffer);
    size_t out_len = cpe_base64_decode((write_stream_t)&ws, (read_stream_t)&is);
    if (out_len >= key_len) {
        memcpy(key, mem_buffer_make_continuous(&processor->m_tmp_buffer, 0), key_len);
        if (processor->m_debug) {
            CPE_INFO(processor->m_em, "crypto: dump key: %s", cpe_hex_dup_buf(key, key_len, &processor->m_tmp_buffer));
        }
        return (int)key_len;
    }

    /*随机生产key */
    randombytes_buf(key, key_len);
    
    CPE_INFO(processor->m_em, "Invalid key for your chosen cipher!");
    CPE_INFO(processor->m_em, "It requires a " FMT_SIZE_T "-byte key encoded with URL-safe Base64", key_len);
    CPE_INFO(
        processor->m_em, "Generating a new random key: %s",
        cpe_base64_dump(&processor->m_tmp_buffer, key, key_len));
    CPE_INFO(processor->m_em, "Please use the key above or input a valid key");
    
    return key_len;
}

int crypto_derive_key(crypto_processor_t processor, const char *pass, uint8_t *key, size_t key_len) {
    size_t datal;
    datal = strlen((const char *)pass);

    const crypto_digest_type * md = mbedtls_md_info_from_string("MD5");
    if (md == NULL) {
        CPE_ERROR(processor->m_em, "MD5 Digest not found in crypto library");
        return -1;
    }

    mbedtls_md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int addmd;
    unsigned int i, j, mds;

    mds = mbedtls_md_get_size(md);
    memset(&c, 0, sizeof(mbedtls_md_context_t));

    if (pass == NULL) {
        return key_len;
    }
    
    if (mbedtls_md_setup(&c, md, 1)) {
        return 0;
    }

    for (j = 0, addmd = 0; j < key_len; addmd++) {
        mbedtls_md_starts(&c);
        if (addmd) {
            mbedtls_md_update(&c, md_buf, mds);
        }
        mbedtls_md_update(&c, (uint8_t *)pass, datal);
        mbedtls_md_finish(&c, &(md_buf[0]));

        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    mbedtls_md_free(&c);
    return key_len;
}

const char * crypto_method_name(crypto_method_t method) {
    switch(method) {
    case crypto_method_stream_rc4:
        return "rc4";
    case crypto_method_stream_rc4_md5:
        return "rc4_md5";
    case crypto_method_stream_aes_128_cfb:
        return "aes-128-cfb";
    case crypto_method_stream_aes_192_cfb:
        return "aes-192-cfb";
    case crypto_method_stream_aes_256_cfb:
        return "aes-256-cfb";
    case crypto_method_stream_aes_128_ctr:
        return "aes-128-ctr";
    case crypto_method_stream_aes_192_ctr:
        return "aes-192-ctr";
    case crypto_method_stream_aes_256_ctr:
        return "aes-256-ctr";
    case crypto_method_stream_bf_cfb:
        return "bf-cfb";
    case crypto_method_stream_camellia_128_cfb:
        return "camellia-128-cfb";
    case crypto_method_stream_camellia_192_cfb:
        return "camellia-192-cfb";
    case crypto_method_stream_camellia_256_cfb:
        return "camellia-256-cfb";
    case crypto_method_stream_cast5_cfb:
        return "cast5-cfb";
    case crypto_method_stream_des_cfb:
        return "des-cfb";
    case crypto_method_stream_idea_cfb:
        return "idea-cfb";
    case crypto_method_stream_rc2_cfb:
        return "rc2-cfb";
    case crypto_method_stream_seed_cfb:
        return "seed-cfb";
    case crypto_method_stream_salsa20:
        return "salsa20";
    case crypto_method_stream_chacha20:
        return "chacha20";
    case crypto_method_stream_chacha20_ietf:
        return "chacha20-ietf";
    case crypto_method_aes_128_gcm:
        return "aes-128-gcm";
    case crypto_method_aes_192_gcm:
        return "aes-192-gcm";
    case crypto_method_aes_256_gcm:
        return "aes-256-gcm";
    case crypto_method_chacha20_ietf_poly1305:
        return "chacha20-ietf-poly1305";
    case crypto_method_xchacha20_ietf_poly1305:
        return "xchacha20-ietf-poly1305";
    default:
        return "unknown";
    }
}

crypto_method_t crypto_method_from_name(const char * method_name) {
    if (strcmp(method_name, "rc4") == 0) {
        return crypto_method_stream_rc4;
    }
    else if (strcmp(method_name, "rc4_md5") == 0) {
        return crypto_method_stream_rc4_md5;
    }
    else if (strcmp(method_name, "aes-128-cfb") == 0) {
        return crypto_method_stream_aes_128_cfb;
    }
    else if (strcmp(method_name, "aes-192-cfb") == 0) {
        return crypto_method_stream_aes_192_cfb;
    }
    else if (strcmp(method_name, "aes-256-cfb") == 0) {
        return crypto_method_stream_aes_256_cfb;
    }
    else if (strcmp(method_name, "aes-128-ctr") == 0) {
        return crypto_method_stream_aes_128_ctr;
    }
    else if (strcmp(method_name, "aes-192-ctr") == 0) {
        return crypto_method_stream_aes_192_ctr;
    }
    else if (strcmp(method_name, "aes-256-ctr") == 0) {
        return crypto_method_stream_aes_256_ctr;
    }
    else if (strcmp(method_name, "bf-cfb") == 0) {
        return crypto_method_stream_bf_cfb;
    }
    else if (strcmp(method_name, "camellia-128-cfb") == 0) {
        return crypto_method_stream_camellia_128_cfb;
    }
    else if (strcmp(method_name, "camellia-192-cfb") == 0) {
        return crypto_method_stream_camellia_192_cfb;
    }
    else if (strcmp(method_name, "camellia-256-cfb") == 0) {
        return crypto_method_stream_camellia_256_cfb;
    }
    else if (strcmp(method_name, "cast5-cfb") == 0) {
        return crypto_method_stream_cast5_cfb;
    }
    else if (strcmp(method_name, "des-cfb") == 0) {
        return crypto_method_stream_des_cfb;
    }
    else if (strcmp(method_name, "idea-cfb") == 0) {
        return crypto_method_stream_idea_cfb;
    }
    else if (strcmp(method_name, "rc2-cfb") == 0) {
        return crypto_method_stream_rc2_cfb;
    }
    else if (strcmp(method_name, "seed-cfb") == 0) {
        return crypto_method_stream_seed_cfb;
    }
    else if (strcmp(method_name, "salsa20") == 0) {
        return crypto_method_stream_salsa20;
    }
    else if (strcmp(method_name, "chacha20") == 0) {
        return crypto_method_stream_chacha20;
    }
    else if (strcmp(method_name, "chacha20-ietf") == 0) {
        return crypto_method_stream_chacha20_ietf;
    }
    else if (strcmp(method_name, "aes-128-gcm") == 0) {
        return crypto_method_aes_128_gcm;
    }
    else if (strcmp(method_name, "aes-192-gcm") == 0) {
        return crypto_method_aes_192_gcm;
    }
    else if (strcmp(method_name, "aes-256-gcm") == 0) {
        return crypto_method_aes_256_gcm;
    }
    else if (strcmp(method_name, "chacha20-ietf-poly1305") == 0) {
        return crypto_method_chacha20_ietf_poly1305;
    }
    else if (strcmp(method_name, "xchacha20-ietf-poly1305") == 0) {
        return crypto_method_xchacha20_ietf_poly1305;
    }
    else {
        return crypto_method_none;
    }
}
