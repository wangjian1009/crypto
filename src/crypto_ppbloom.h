#ifndef CRYPTO_PPBLOOM_I_H_INCLEDED
#define CRYPTO_PPBLOOM_I_H_INCLEDED
#include "bloom.h"
#include "crypto_processor_i.h"

CRYPTO_BEGIN_DECL

struct crypto_ppbloom {
    mem_allocrator_t m_alloc;
    error_monitor_t m_em;
    struct bloom ppbloom[2];
    int bloom_count[2];
    int current;
    int entries;
    double error;
};

crypto_ppbloom_t crypto_ppbloom_create(mem_allocrator_t alloc, error_monitor_t em, int entries, double error);
int crypto_ppbloom_check(crypto_ppbloom_t ppbloom, const void *buffer, int len);
int crypto_ppbloom_add(crypto_ppbloom_t ppbloom, const void *buffer, int len);
void crypto_ppbloom_free(crypto_ppbloom_t ppbloom);

CRYPTO_END_DECL

#endif
