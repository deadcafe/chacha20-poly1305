#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

#include "chacha_xxx.h"

typedef __m128i uint128_t;

/* GCC */
//typedef unsigned uint128_t __attribute__((mode(TI)));


typedef union {
        uint128_t v128;
        uint64_t v64[2];
        uint32_t v32[4];
        uint8_t  v8[16];
} U128;

/*****************************************************************************
 * chacha20
 *****************************************************************************/
/*
 * chacha state on SSE(x4)
 */
struct chacha_state_sse_s {
        uint128_t v[16];
};

union chacha_key_u {
        uint8_t v8[32];
        uint32_t v32[4];
};

static const uint32_t constant_value[4] = {
        0x65787061, 0x6e642033, 0x322d6279, 0x7465206b,
};


#define DOUBLE_QUARTER_ROUND(v0,v1,v2,v3)       \
        do {                                    \
                uint128_t x, y;                 \
                                                \
                /*                              \
                 * v0 += v1;                    \
                 * v3 ^= v0;                    \
                 * v3 <<<= (16, 16, 16, 16);    \
                 */                             \
                v0 = _mm_add_epi32(v0, v1);     \
                v3 = _mm_xor_si128(v3, v0);     \
                x  = _mm_sll_epi32(v3, 16);     \
                y  = _mm_srl_epi32(v3, 16);     \
                v3 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v2 += v3;                    \
                 * v1 ^= v2;                    \
                 * v1 <<<= (12, 12, 12, 12);    \
                 */                             \
                v2 = _mm_add_epi32(v2, v3);     \
                v1 = _mm_xor_si128(v1, v2);     \
                x  = _mm_sll_epi32(v1, 12);     \
                y  = _mm_srl_epi32(v1, 20);     \
                v1 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v0 += v1;                    \
                 * v3 ^= v0;                    \
                 * v3 <<<= ( 8,  8,  8,  8);    \
                 */                             \
                v0 = _mm_add_epi32(v0, v1);     \
                v3 = _mm_xor_si128(v3, v0);     \
                x  = _mm_sll_epi32(v3, 8);      \
                y  = _mm_srl_epi32(v3, 24);     \
                v3 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v2 += v3;                    \
                 * v1 ^= v2;                    \
                 * v1 <<<= ( 7,  7,  7,  7);    \
                 */                             \
                v2 = _mm_add_epi32(v2, v3);     \
                v1 = _mm_xor_si128(v1, v2);     \
                x  = _mm_sll_epi32(v1, 7);      \
                y  = _mm_srl_epi32(v1, 25);     \
                v1 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v1 >>>= 32;                  \
                 * v2 >>>= 64;                  \
                 * v3 >>>= 96;                  \
                 */                             \
                x  = _mm_srli_si128(v1, 4);     \
                y  = _mm_slli_si128(v1, 12);    \
                v1 = _mm_or_pd(x, y);           \
                                                \
                x  = _mm_srli_si128(v2, 8);     \
                y  = _mm_slli_si128(v2, 8);     \
                v2 = _mm_or_pd(x, y);           \
                                                \
                x  = _mm_srli_si128(v3, 12);    \
                y  = _mm_slli_si128(v3, 4);     \
                v3 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v0 += v1;                    \
                 * v3 ^= v0;                    \
                 * v3 <<<= (16, 16, 16, 16);    \
                 */                             \
                v0 = _mm_add_epi32(v0, v1);     \
                v3 = _mm_xor_si128(v3, v0);     \
                x  = _mm_sll_epi32(v3, 16);     \
                y  = _mm_srl_epi32(v3, 16);     \
                v3 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v2 += v3;                    \
                 * v1 ^= v2;                    \
                 * v1 <<<= (12, 12, 12, 12);    \
                 */                             \
                v2 = _mm_add_epi32(v2, v3);     \
                v1 = _mm_xor_si128(v1, v2);     \
                x  = _mm_sll_epi32(v1, 12);     \
                y  = _mm_srl_epi32(v1, 20);     \
                v1 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v0 += v1;                    \
                 * v3 ^= v0;                    \
                 * v3 <<<= ( 8,  8,  8,  8);    \
                 */                             \
                v0 = _mm_add_epi32(v0, v1);     \
                v3 = _mm_xor_si128(v3, v0);     \
                x  = _mm_sll_epi32(v3, 8);      \
                y  = _mm_srl_epi32(v3, 24);     \
                v3 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v2 += v3;                    \
                 * v1 ^= v2;                    \
                 * v1 <<<= ( 7,  7,  7,  7);    \
                 */                             \
                v2 = _mm_add_epi32(v2, v3);     \
                v1 = _mm_xor_si128(v1, v2);     \
                x  = _mm_sll_epi32(v1, 7);      \
                y  = _mm_srl_epi32(v1, 25);     \
                v1 = _mm_or_pd(x, y);           \
                                                \
                /*                              \
                 * v1 <<<= 32;                  \
                 * v2 <<<= 64;                  \
                 * v3 <<<= 96;                  \
                 */                             \
                x  = _mm_srli_si128(v1, 4);     \
                y  = _mm_slli_si128(v1, 12);    \
                v1 = _mm_or_pd(x, y);           \
                                                \
                x  = _mm_srli_si128(v2, 8);     \
                y  = _mm_slli_si128(v2, 8);     \
                v2 = _mm_or_pd(x, y);           \
                                                \
                x  = _mm_srli_si128(v3, 12);    \
                y  = _mm_slli_si128(v3, 4);     \
                v3 = _mm_or_pd(x, y);           \
        } while (0)

static inline void
DOUBLE_ROUND(uint128_t v[16])
{
        DOUBLE_QUARTER_ROUND(v[0x0], v[0x4], v[0x8], v[0xc]);
        DOUBLE_QUARTER_ROUND(v[0x1], v[0x5], v[0x9], v[0xd]);
        DOUBLE_QUARTER_ROUND(v[0x2], v[0x6], v[0xa], v[0xe]);
        DOUBLE_QUARTER_ROUND(v[0x3], v[0x7], v[0xb], v[0xf]);
        DOUBLE_QUARTER_ROUND(v[0x0], v[0x5], v[0xa], v[0xf]);
        DOUBLE_QUARTER_ROUND(v[0x1], v[0x6], v[0xb], v[0xc]);
        DOUBLE_QUARTER_ROUND(v[0x2], v[0x7], v[0x8], v[0xd]);
        DOUBLE_QUARTER_ROUND(v[0x3], v[0x4], v[0x9], v[0xe]);
}

static void
double_round(uint128_t *p)
{
        DOUBLE_ROUND(p);
}






/*
 * initialize chacha state 4 blocks
 */
static inline void
chacha_init(struct chacha_state_sse_s st[4],
            
            const uint128_t key[2],
            const uint32_t salt[1],
            const uint32_t iv[2],
            const uint32_t ctr)
{
        for (uint32_t i = 0; i < 4; i++) {
                
                st[i].v[0].v128   = constant_value;
                st[i].v[1].v128   = key[0];
                st[i].v[2].v128   = key[1];
                st[i].v[3].v32[0] = ctr + i;
                st[i].v[3].v32[1] = salt[0];
                st[i].v[3].v32[2] = iv[0];
                st[i].v[3].v32[3] = iv[1];
        }
}

/*****************************************************************************
 * poly1305
 *****************************************************************************/
struct poly_key_s {
        uint8_t v[256 / 8];
};

struct poly_state_s {
        uint8_t v[32];
};

static void
poly_update(struct poly_state_s *state,
            uint128_t block)
{
        
}

static void
poly_update_blocks(struct poly_state_s *state,
                   const uint128_t *blocks,
                   unsigned nb_blocks)
{
        while (nb_blocks) {
                poly_update(state, *blocks);
                blocks++;
        }
}

/*
 *
 */
static void
poly_update_w_zpad(struct poly_state_s *state,
                   const uint8_t *src,
                   uint64_t len)
{
        while (len >= 16) {
                poly_update(state, *((const uint128_t *) src));
                len -= 16;
        }

        if (len) {
                uint8_t v[16];

                memset(v, 0, 16);
                memcpy(v, src, len);
                poly_update(state, *((const uint128_t *) v));
        }
}

/******************************************************************************
 * rfc7634
 * key:
 *   first 32 bytes: chacha20 key
 *   remaining 4 bytes: salt
 * aad_len:
 * return
 * 	0:     success
 *      other: failed
 *****************************************************************************/
/* length in bits */
#define CHACHA_KEY_LEN		256
#define CHACHA_SALT_LEN		32
#define CHACHA_IV_LEN		64
#define CHACHA_BLOCK_LEN	512

#define POLY_TAG_LEN		128
#define POLY_KEY_LEN
#define POLY_BLOCK_LEN


void
chacha_poly_enc_sse(uint8_t *dst,
                    uint8_t tag[POLY_TAG_LEN / 8],
                    const uint8_t *src,
                    uint64_t len,
                    const uint8_t *aad,
                    uint64_t aad_len,
                    const uint8_t key[CHACHA_KEY_LEN / 8],
                    const uint8_t salt[CHACHA_SALT_LEN / 8],
                    const uint8_t iv[CHACHA_IV_LEN / 8])
{
        struct chacha_state_s chacha_state[4];
        struct poly_state_s poly_state;
        struct poly_key_s *poly_key = (struct poly_key_s *) &chacha_state[0];
        unsigned nb_blocks;
        umsigned ctr = 0;
        offset_t offset = dst - src;
        struct {
                uint64_t aad_length;
                uint64_t cipher_length;
        } total_length;

        total_length.aad_length = aad_len;
        total_length.cipher_length = len;

        nb_blocks = len / 64;
        if (len & 63)
                nb_blocks += 2;
        else
                nb_blocks += 1;

        if (nb_blocks > 5)
                nb = 5;
        else
                nb = nb_blocks;

        chacha_init(chacha_state, key, iv, ctr, nb);
        ctr += nb;

        poly_init(&poly_state, poly_key);
        poly_update_w_zpad(&poly_state, aad, aad_len);

        /* powered by SSE */
        while (len > (64 * 4)) {
                chacha_init(&chacha_state[1], key, iv, ctr, nb);
                chacha_update_blocks(chacha_state, dst, offset, 4);
                poly_update_blocks(&poly_state, dst, offset, 4 * 4);

                len -= (64 * 4);
                dst += (64 * 4);
                ctr += nb;
        }

        while (len > 64) {
                chacha_init(&chacha_state[1], key, iv, ctr, nb);
                chacha_update_blocks(chacha_state, dst, offset, 1);
                poly_update_blocks(&poly_state, dst, offset, 4);

                len -= 64;
                dst += 64;
                ctr += nb;
        }

        if (len) {
                chacha_init(&chacha_state[1], key, iv, ctr, nb);
                chacha_update(chacha_state, dst, offset, len);

                while (len >= 16) {
                        poly_update(&poly_state, dst);
                        dst += 16;
                        len -= 16;
                }

                if (len)
                        poly_update_w_zpad(&poly_state, dst, len);
        }
        poly_update(&poly_state, total_length);
        poly_final(&poly_state, tag);
}

