#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>

#include "chacha20.h"
#include "poly1305.h"

enum cipher_direction_e {
        CIPHER_DIR_ENCRYPT = 0,
        CIPHER_DIR_DECRYPT,
};

struct chacha20_poly1305_ctx {
        uint32_t chacha20_state[16];
        struct poly1305_state_s poly1305_state;
};

extern int aead_chacha20_poly1305(const uint8_t key[CHACHA_KEYLEN],
                                  enum cipher_direction_e dir,
                                  const uint8_t nonce[CHACHA_NONCELEN],
                                  uint8_t *out,
                                  const uint8_t *in,
                                  unsigned inlen,
                                  const uint8_t *aad,
                                  unsigned aad_len,
                                  uint8_t tag[POLY1305_TAGLEN]);



#endif /* !CHACHA20_POLY1305_H */

