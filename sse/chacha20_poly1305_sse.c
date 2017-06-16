
#include <x86intrin.h>

/*
 * SSSE3 x86_64
 */

static const unsigned char ROT8[16] = {
        0x0e, 0x0d, 0x0c, 0x0f, 0x0a, 0x09, 0x08, 0x0b,
        0x06, 0x05, 0x04, 0x07, 0x02, 0x01, 0x00, 0x03,
} __attribute__((aligned(16)));

static const unsigned char ROT16[16] = {
        0x0d, 0x0c, 0x0f, 0x0e, 0x09, 0x08, 0x0b, 0x0a,
        0x05, 0x04, 0x07, 0x06, 0x01, 0x00, 0x03, 0x02,
} __attribute__((aligned(16)));

static const unsigned char CTRINC[16] = {
        0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
} __attribute__((aligned(16)));


/*
 * XMM := 32x4
 */
chacha_doubleround_4blocks(x0, x1, x2, x3, rt16, rt8) {
        /* x0 += x1, x3 = rotl32(x3 ^ x0, 16) */
        x0 = _mm_add_epi32(x0, x1);
        x3 = _mm_xor_si128(x3, x0);
        x3 = _mm_shuffle_epi8(x3, rt16);

        /* x2 += x3, x1 = rotl32(x1 ^ x2, 12) */
        x2 = _mm_add_epi32(x2, x3);
        x1 = _mm_xor_si128(x1, x2);
        xx = _mm_slli_epi32(x1, 12);
        x1 = _mm_srli_epi32(x1, 20);
        x1 = _mm_xor_si128(x1, xx);

        /* x0 += x1, x3 = rotl32(x3 ^ x0, 8) */
        x0 = _mm_add_epi32(x0, x1);
        x3 = _mm_xor_si128(x3, x0);
        x3 = _mm_shuffle_epi8(x3, rt8);

        /* x2 += x3, x1 = rotl32(x1 ^ x2, 7) */

        /* x1 = shuffle32(x1, MASK(0, 3, 2, 1)) */

        /* x2 = shuffle32(x2, MASK(1, 0, 3, 2)) */

        /* x3 = shuffle32(x3, MASK(2, 1, 0, 3)) */


        /* x0 += x1, x3 = rotl32(x3 ^ x0, 16) */

        /* x2 += x3, x1 = rotl32(x1 ^ x2, 12) */

        /* x0 += x1, x3 = rotl32(x3 ^ x0, 8) */

        /* x2 += x3, x1 = rotl32(x1 ^ x2, 7) */

        /* x1 = shuffle32(x1, MASK(2, 1, 0, 3)) */

        /* x2 = shuffle32(x2, MASK(1, 0, 3, 2)) */

        /* x3 = shuffle32(x3, MASK(0, 3, 2, 1)) */
}






int
chacha20_poly1305_enc_sse(const void *key,
                          
                          void *tag,
                          void *dst,
                          void *src,
                          size_t len)
{
        xmm0, xmm1, xmm2, xmm3;



}

int
chacha20_poly1305_dec_sse(const void *key,
                          void *tag,
                          void *dst,
                          void *src,
                          size_t len)
{




}
