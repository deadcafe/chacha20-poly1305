#ifndef _CHACHA_XXX_H_
#define _CHACHA_XXX_H_

#include <stdint.h>
#include <stddef.h>

extern void chacha_poly_enc(const uint8_t key[32],
                            uint8_t *dst,
                            uint8_t tag[16],
                            const uint8_t *src,
                            size_t len,
                            const uint8_t salt[4],
                            const uint8_t iv[8],
                            const uint8_t *aad,
                            size_t aad_len);

extern void chacha_poly_dec(const uint8_t key[32],
                            uint8_t *dst,
                            uint8_t tag[16],
                            const uint8_t *src,
                            size_t len,
                            const uint8_t salt[4],
                            const uint8_t iv[8],
                            const uint8_t *aad,
                            size_t aad_len);

#endif /* !_CHACHA_XXX_H_ */
