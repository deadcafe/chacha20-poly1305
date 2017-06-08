#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>

#include "chacha20.h"
#include "poly1305.h"

struct chacha20_poly1305_ctx {
        uint32_t chacha20_state[16];
        struct poly1305_state_s poly1305_state;
};


extern void chacha20_poly1305_enc(const uint8_t key[CHACHA_KEYLEN],
                                  const uint8_t nonce[CHACHA_NONCELEN],
                                  uint8_t *out,
                                  const uint8_t *in,
                                  unsigned inlen,
                                  const uint8_t *aad,
                                  unsigned aad_len,
                                  uint8_t tag[POLY1305_TAGLEN]);



#endif /* !CHACHA20_POLY1305_H */

