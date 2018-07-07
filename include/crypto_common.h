#ifndef CRYPTO_COMMON_H_INCLEDED
#define CRYPTO_COMMON_H_INCLEDED
#include "cpe/pal/pal_types.h"

#ifdef __cplusplus
#  define CRYPTO_BEGIN_DECL extern "C" {
#  define CRYPTO_END_DECL }
#else
#  define CRYPTO_BEGIN_DECL
#  define CRYPTO_END_DECL
#endif

#endif

