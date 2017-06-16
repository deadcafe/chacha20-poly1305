#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

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


#define DOUBLE_QUARTER_ROUND(v0,v1,v2,v3)               \
        do {                                            \
                uint128_t x,y;                          \
                                                        \
                /*                                      \
                 * v0 += v1;                            \
                 * v3 ^= v0;                            \
                 * v3 <<<= (16, 16, 16, 16);            \
                 */                                     \
                v0 = _mm_add_epi32(v0, v1);             \
                v3 = _mm_xor_si128(v3, v0);             \
                x  = _mm_slli_epi32(v3, 16);            \
                y  = _mm_srli_epi32(v3, 16);            \
                v3 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v2 += v3;                            \
                 * v1 ^= v2;                            \
                 * v1 <<<= (12, 12, 12, 12);            \
                 */                                     \
                v2 = _mm_add_epi32(v2, v3);             \
                v1 = _mm_xor_si128(v1, v2);             \
                x  = _mm_slli_epi32(v1, 12);            \
                y  = _mm_srli_epi32(v1, 20);            \
                v1 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v0 += v1;                            \
                 * v3 ^= v0;                            \
                 * v3 <<<= ( 8,  8,  8,  8);            \
                 */                                     \
                v0 = _mm_add_epi32(v0, v1);             \
                v3 = _mm_xor_si128(v3, v0);             \
                x  = _mm_slli_epi32(v3, 8);             \
                y  = _mm_srli_epi32(v3, 24);            \
                v3 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v2 += v3;                            \
                 * v1 ^= v2;                            \
                 * v1 <<<= ( 7,  7,  7,  7);            \
                 */                                     \
                v2 = _mm_add_epi32(v2, v3);             \
                v1 = _mm_xor_si128(v1, v2);             \
                x  = _mm_slli_epi32(v1, 7);             \
                y  = _mm_srli_epi32(v1, 25);            \
                v1 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v1 >>>= 32;                          \
                 * v2 >>>= 64;                          \
                 * v3 >>>= 96;                          \
                 */                                     \
                x  = _mm_srli_si128(v1, 4);             \
                y  = _mm_slli_si128(v1, 12);            \
                v1 = _mm_or_si128(x, y);                \
                                                        \
                x  = _mm_srli_si128(v2, 8);             \
                y  = _mm_slli_si128(v2, 8);             \
                v2 = _mm_or_si128(x, y);                \
                                                        \
                x  = _mm_srli_si128(v3, 12);            \
                y  = _mm_slli_si128(v3, 4);             \
                v3 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v0 += v1;                            \
                 * v3 ^= v0;                            \
                 * v3 <<<= (16, 16, 16, 16);            \
                 */                                     \
                v0 = _mm_add_epi32(v0, v1);             \
                v3 = _mm_xor_si128(v3, v0);             \
                x  = _mm_slli_epi32(v3, 16);            \
                y  = _mm_srli_epi32(v3, 16);            \
                v3 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v2 += v3;                            \
                 * v1 ^= v2;                            \
                 * v1 <<<= (12, 12, 12, 12);            \
                 */                                     \
                v2 = _mm_add_epi32(v2, v3);             \
                v1 = _mm_xor_si128(v1, v2);             \
                x  = _mm_slli_epi32(v1, 12);            \
                y  = _mm_srli_epi32(v1, 20);            \
                v1 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v0 += v1;                            \
                 * v3 ^= v0;                            \
                 * v3 <<<= ( 8,  8,  8,  8);            \
                 */                                     \
                v0 = _mm_add_epi32(v0, v1);             \
                v3 = _mm_xor_si128(v3, v0);             \
                x  = _mm_slli_epi32(v3, 8);             \
                y  = _mm_srli_epi32(v3, 24);            \
                v3 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v2 += v3;                            \
                 * v1 ^= v2;                            \
                 * v1 <<<= ( 7,  7,  7,  7);            \
                 */                                     \
                v2 = _mm_add_epi32(v2, v3);             \
                v1 = _mm_xor_si128(v1, v2);             \
                x  = _mm_slli_epi32(v1, 7);             \
                y  = _mm_srli_epi32(v1, 25);            \
                v1 = _mm_or_si128(x, y);                \
                                                        \
                /*                                      \
                 * v1 <<<= 32;                          \
                 * v2 <<<= 64;                          \
                 * v3 <<<= 96;                          \
                 */                                     \
                x  = _mm_srli_si128(v1, 4);             \
                y  = _mm_slli_si128(v1, 12);            \
                v1 = _mm_or_si128(x, y);                \
                                                        \
                x  = _mm_srli_si128(v2, 8);             \
                y  = _mm_slli_si128(v2, 8);             \
                v2 = _mm_or_si128(x, y);                \
                                                        \
                x  = _mm_srli_si128(v3, 12);            \
                y  = _mm_slli_si128(v3, 4);             \
                v3 = _mm_or_si128(x, y);                \
                                                        \
        } while (0)


static inline void
double_round(uint128_t v[16])
{
        DOUBLE_QUARTER_ROUND(v[0], v[4], v[8],  v[12]);
        DOUBLE_QUARTER_ROUND(v[1], v[5], v[9],  v[13]);
        DOUBLE_QUARTER_ROUND(v[2], v[6], v[10], v[14]);
        DOUBLE_QUARTER_ROUND(v[3], v[7], v[11], v[15]);

        DOUBLE_QUARTER_ROUND(v[0], v[5], v[10], v[15]);
        DOUBLE_QUARTER_ROUND(v[1], v[6], v[11], v[12]);
        DOUBLE_QUARTER_ROUND(v[2], v[7], v[8],  v[13]);
        DOUBLE_QUARTER_ROUND(v[3], v[4], v[9],  v[14]);
}

static inline void
block_round(uint128_t blocks[16],
            const uint128_t state[16])
{
        memcpy(blocks, state, sizeof(blocks))l
        for (unsigned rounds = 10; rounds; rounds--)
                double_round(blocks);

        for (unsigned i = 0; i < 16; i++)
                blocks[i] = _mm_add_epi32(blocks[i], state[i]);

        
}



static inline void
chacha_block(uint32_t blocks[16][4],
             uint128_t state[16])
{
        unsigned nb_blocks;
        uint128_t blocks[16];

        nb_blocks = (src_len / 64) + 2;

        if (nb_blocks >= 4) {



        }
}





static void
init_state_sse(uint128_t v[16],
               const uint8_t key[32],
               const uint8_t salt[4],
               const uint8_t iv[8])
{
        const uint32_t constant_value[4] = {
                0x65787061, 0x6e642033, 0x322d6279, 0x7465206b,
        };
        const uint32_t counter_value[4] = {
                0, 1, 2, 3,
        };
        uint128_t x;

        /* expand 32-byte k */
        x = _mm_loadu_si128(constant_value);
        v[0] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[1] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[2] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[3] = _mm_broadcastd_epi32(x);

        /* key */
        x = _mm_loadu_si128(&key[0]);
        v[4] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[5] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[6] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[7] = _mm_broadcastd_epi32(x);

        x = _mm_loadu_si128(&key[16]);
        v[8] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[9] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[10] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[11] = _mm_broadcastd_epi32(x);

        /* counter */
        x = _mm_loadu_si128(&counter_value);
        v[12] = _mm_broadcastd_epi32(x);

        /* salt */
        x = _mm_loadu_si128(salt);
        v[13] = _mm_broadcastd_epi32(x);

        /* iv */
        x = _mm_loadu_si128(iv);
        v[14] = _mm_broadcastd_epi32(x);

        x = _mm_srli_si128(x, 4);
        v[15] = _mm_broadcastd_epi32(x);
}

static void
update_state_sse(uint128_t v[16])
{
        const uint32_t counter_update[4] = {
                4, 4, 4, 4,
        };
        uint128_t x;

        x = _mm_loadu_si128(counter_update);
        v[12] = _mm_add_epi32(v[12], x);
}


