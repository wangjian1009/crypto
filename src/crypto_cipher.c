#include "crypto_cipher.h"

void crypto_cipher_free(crypto_processor_t processor, crypto_cipher_t cipher) {
    switch(cipher->method) {
    case crypto_method_stream_salsa20:
    case crypto_method_stream_chacha20:
    case crypto_method_stream_chacha20_ietf:
        mem_free(processor->m_alloc, cipher->info);
        break;
    default:
        break;
    }
    
    mem_free(processor->m_alloc, cipher);
}

