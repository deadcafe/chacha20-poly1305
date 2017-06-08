#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>

#define CHACHA_KEYLEN 	        32
#define CHACHA_NONCELEN		12
#define CHACHA_CTRLEN		4
#define CHACHA_STATELEN		(CHACHA_NONCELEN + CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

struct chacha20_key_s {
        uint8_t val[CHACHA_KEYLEN];
};

struct chacha20_ctx_s {
        uint32_t state[16];
};

/* one-shot */
extern void chacha20(const struct chacha20_key_s *key,
                     uint8_t *out,
                     const uint8_t *in,
                     unsigned inLen,
                     const uint8_t nonce[CHACHA_NONCELEN],
                     uint32_t counter);

extern void chacha20_init(const struct chacha20_key_s *key,
                          struct chacha20_ctx_s *state,
                          const uint8_t nonce[CHACHA_NONCELEN],
                          uint32_t counter);

extern void chacha20_block(struct chacha20_ctx_s *state,
                           uint8_t *out,
                           const uint8_t *in,
                           unsigned inLen);

#endif	/* CHACHA20_H */

