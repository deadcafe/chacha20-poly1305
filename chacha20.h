#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>

#define CHACHA_KEYLEN 	        32
#define CHACHA_NONCELEN		12
#define CHACHA_CTRLEN		4
#define CHACHA_STATELEN		(CHACHA_NONCELEN + CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64


extern void chacha20(uint8_t *out,
                     const uint8_t *in,
                     unsigned inLen,
                     const uint8_t key[CHACHA_KEYLEN],
                     const uint8_t nonce[CHACHA_NONCELEN],
                     uint32_t counter);

extern void chacha20_init(uint32_t state[16],
                          const uint8_t key[CHACHA_KEYLEN],
                          const uint8_t nonce[CHACHA_NONCELEN],
                          uint32_t counter);
extern void chacha20_block(uint8_t *out,
                           const uint8_t *in,
                           unsigned inLen,
                           uint32_t state[16]);


#endif	/* CHACHA20_H */

