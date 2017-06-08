#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "chacha20.h"
#include "tools.h"


#define U8V(v)  ((uint8_t)  (v) & UINT8_C(0xFF))
#define U32V(v) ((uint32_t) (v) & UINT32_C(0xFFFFFFFF))


#define U8TO32_LE(p)                            \
        (((uint32_t) ((p)[0])      ) |          \
         ((uint32_t) ((p)[1]) <<  8) |          \
         ((uint32_t) ((p)[2]) << 16) |          \
         ((uint32_t) ((p)[3]) << 24))

#define U32TO8_LE(p, v)                         \
        do {                                    \
                (p)[0] = U8V((v)      );        \
                (p)[1] = U8V((v) >>  8);        \
                (p)[2] = U8V((v) >> 16);        \
                (p)[3] = U8V((v) >> 24);        \
        } while (0)

#define ROTL32(v,n)     (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define ROTATE(v,c)     (ROTL32((v), (c)))
#define XOR(v,w)        ((v) ^ (w))
#define PLUS(v,w)   	(U32V((v) + (w)))
#define PLUSONE(v)  	(PLUS((v), 1))

#define QUARTERROUND(a,b,c,d)                                           \
        do {                                                            \
                (a) = PLUS((a),(b)); (d) = ROTATE(XOR((d),(a)),16);     \
                (c) = PLUS((c),(d)); (b) = ROTATE(XOR((b),(c)),12);     \
                (a) = PLUS((a),(b)); (d) = ROTATE(XOR((d),(a)), 8);     \
                (c) = PLUS((c),(d)); (b) = ROTATE(XOR((b),(c)), 7);     \
        } while (0)


struct quarter_round_s {
        uint8_t a;
        uint8_t b;
        uint8_t c;
        uint8_t d;
};

static const struct quarter_round_s quarter_round_dic[] = {
        { 0, 4,  8, 12, },
        { 1, 5,  9, 13, },
        { 2, 6, 10, 14, },
        { 3, 7, 11, 15, },
        { 0, 5, 10, 15, },
        { 1, 6, 11, 12, },
        { 2, 7,  8, 13, },
        { 3, 4,  9, 14, },
};

static inline void
quarter_round(uint32_t x[16],
              const struct quarter_round_s dic[8],
              unsigned num_rounds)
{
        while (num_rounds) {
                for (unsigned i = 0; i < 8; i++)
                        QUARTERROUND(x[dic[i].a],
                                     x[dic[i].b],
                                     x[dic[i].c],
                                     x[dic[i].d]);
                num_rounds -= 2;
        }
}

static inline void
chacha_rounds(uint8_t output[64],
              const uint32_t input[16],
              int num_rounds)
{
        uint32_t x[16] __attribute__((aligned(64)));
        int i;

        memcpy(x, input, sizeof(x));
        for (i = num_rounds; i > 0; i -= 2) {
                QUARTERROUND( x[0], x[4], x[8],  x[12]);
                QUARTERROUND( x[1], x[5], x[9],  x[13]);
                QUARTERROUND( x[2], x[6], x[10], x[14]);
                QUARTERROUND( x[3], x[7], x[11], x[15]);
                QUARTERROUND( x[0], x[5], x[10], x[15]);
                QUARTERROUND( x[1], x[6], x[11], x[12]);
                QUARTERROUND( x[2], x[7], x[8],  x[13]);
                QUARTERROUND( x[3], x[4], x[9],  x[14]);
        }

        for (i = 0; i < 16; ++i)
                x[i] = PLUS(x[i], input[i]);
        dump_state("ChaChaCore 20 rounds", x);

        for (i = 0; i < 16; ++i)
                U32TO8_LE(output + 4 * i, x[i]);

        dump_state("ChaChaCore final", (const uint32_t *) output);
}

static inline void
chacha_init(uint32_t state[16],
            const uint8_t key[CHACHA_KEYLEN],
            const uint8_t nonce[CHACHA_NONCELEN],
            uint32_t counter)
{
        static const uint8_t __attribute__((aligned(16))) SIGMA[16] = "expand 32-byte k";

        state[4]  = U8TO32_LE(key + 0);
        state[5]  = U8TO32_LE(key + 4);
        state[6]  = U8TO32_LE(key + 8);
        state[7]  = U8TO32_LE(key + 12);
        state[8]  = U8TO32_LE(key + 16);
        state[9]  = U8TO32_LE(key + 20);
        state[10] = U8TO32_LE(key + 24);
        state[11] = U8TO32_LE(key + 28);
        state[0]  = U8TO32_LE(SIGMA + 0);
        state[1]  = U8TO32_LE(SIGMA + 4);
        state[2]  = U8TO32_LE(SIGMA + 8);
        state[3]  = U8TO32_LE(SIGMA + 12);
        state[12] = counter;
        state[13] = U8TO32_LE(nonce + 0);
        state[14] = U8TO32_LE(nonce + 4);
        state[15] = U8TO32_LE(nonce + 8);
}

void
chacha20_init(uint32_t state[16],
              const uint8_t key[CHACHA_KEYLEN],
              const uint8_t nonce[CHACHA_NONCELEN],
              uint32_t counter)
{
        chacha_init(state, key, nonce, counter);
}


void
chacha20_block(uint8_t *out,
               const uint8_t *in,
               unsigned inLen,
               uint32_t state[16])
{
        uint8_t block[CHACHA_BLOCKLEN] __attribute__((aligned(64)));

        chacha_rounds(block, state, 20);
        for (unsigned i = 0; i < inLen; i++)
                out[i] = in[i] ^ block[i];

        state[12]++;
}

void
chacha20(uint8_t *out,
         const uint8_t *in,
         unsigned inLen,
         const uint8_t key[CHACHA_KEYLEN],
         const uint8_t nonce[CHACHA_NONCELEN],
         uint32_t counter)
{
        uint8_t block[CHACHA_BLOCKLEN] __attribute__((aligned(64)));
        uint32_t state[16] __attribute__((aligned(64)));
        unsigned i;

        fprintf(stderr, "%s: out:%p in:%p len:%u counter:%u\n",
                __func__, out, in, inLen, counter);

        chacha_init(state, key, nonce, counter);

        while (inLen >= CHACHA_BLOCKLEN) {
                chacha_rounds(block, state, 20);
                for (i = 0; i < CHACHA_BLOCKLEN; i++)
                        out[i] = in[i] ^ block[i];

                state[12]++;
                inLen -= CHACHA_BLOCKLEN;
                in    += CHACHA_BLOCKLEN;
                out   += CHACHA_BLOCKLEN;
        }

        if (inLen) {
                chacha_rounds(block, state, 20);
                for (i = 0; i < inLen; i++)
                        out[i] = in[i] ^ block[i];
        }
}

