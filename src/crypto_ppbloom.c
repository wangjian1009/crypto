#include "crypto_ppbloom.h"

#define PING 0
#define PONG 1

crypto_ppbloom_t
crypto_ppbloom_create(mem_allocrator_t alloc, error_monitor_t em, int n, double e) {
    crypto_ppbloom_t ppbloom = mem_alloc(alloc, sizeof(struct crypto_ppbloom));
    if (ppbloom == NULL) {
        CPE_ERROR(em, "crypto_ppbloom_create: alloc fail!");
        return NULL;
    }

    ppbloom->m_alloc = alloc;
    ppbloom->m_em = em;
    ppbloom->entries = n / 2;
    ppbloom->error = e;

    int err;

    err = bloom_init(ppbloom->ppbloom + PING, ppbloom->entries, ppbloom->error);
    if (err) {
        CPE_ERROR(em, "crypto_ppbloom_create: bloom init fail!");
        mem_free(alloc, ppbloom);
        return NULL;
    }

    err = bloom_init(ppbloom->ppbloom + PONG, ppbloom->entries, ppbloom->error);
    if (err) {
        CPE_ERROR(em, "crypto_ppbloom_create: bloom init fail!");
        bloom_free(ppbloom->ppbloom + PING);
        mem_free(alloc, ppbloom);
        return NULL;
    }

    ppbloom->bloom_count[PING] = 0;
    ppbloom->bloom_count[PONG] = 0;
    ppbloom->current = PING;

    return ppbloom;
};

void crypto_ppbloom_free(crypto_ppbloom_t ppbloom) {
    bloom_free(ppbloom->ppbloom + PING);
    bloom_free(ppbloom->ppbloom + PONG);
    mem_free(ppbloom->m_alloc, ppbloom);
}

int crypto_ppbloom_check(crypto_ppbloom_t ppbloom, const void *buffer, int len) {
    int ret;

    ret = bloom_check(ppbloom->ppbloom + PING, buffer, len);
    if (ret) {
        return ret;
    }

    ret = bloom_check(ppbloom->ppbloom + PONG, buffer, len);
    if (ret) {
        return ret;
    }

    return 0;
}

int crypto_ppbloom_add(crypto_ppbloom_t ppbloom, const void *buffer, int len) {
    int err;

    err = bloom_add(ppbloom->ppbloom + ppbloom->current, buffer, len);
    if (err == -1)
        return err;

    ppbloom->bloom_count[ppbloom->current]++;

    if (ppbloom->bloom_count[ppbloom->current] >= ppbloom->entries) {
        ppbloom->bloom_count[ppbloom->current] = 0;
        ppbloom->current = ppbloom->current == PING ? PONG : PING;
        bloom_free(ppbloom->ppbloom + ppbloom->current);
        bloom_init(ppbloom->ppbloom + ppbloom->current, ppbloom->entries, ppbloom->error);
    }

    return 0;
}
