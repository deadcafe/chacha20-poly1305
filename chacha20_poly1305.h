#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>

#include "chacha20.h"
#include "poly1305.h"

extern int aead_chacha20_poly1305_enc(const struct chacha20_key_s *chacha20_key,
                                      const uint8_t nonce[CHACHA_NONCELEN],
                                      uint8_t *out,
                                      const uint8_t *in,
                                      unsigned inlen,
                                      const uint8_t *aad,
                                      unsigned aad_len,
                                      uint8_t tag[POLY1305_TAGLEN]);

extern int aead_chacha20_poly1305_dec(const struct chacha20_key_s *chacha20_key,
                                      const uint8_t nonce[CHACHA_NONCELEN],
                                      uint8_t *out,
                                      const uint8_t *in,
                                      unsigned inlen,
                                      const uint8_t *aad,
                                      unsigned aad_len,
                                      const uint8_t tag[POLY1305_TAGLEN]);


#endif /* !CHACHA20_POLY1305_H */

