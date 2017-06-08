
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "poly1305.h"
#include "tools.h"

#define mul32x32_64(a,b) ((uint64_t) (a) * (b))

#define U8V(v)  ((uint8_t)  (v) & UINT8_C(0xFF))
#define U32V(v) ((uint32_t) (v) & UINT32_C(0xFFFFFFFF))

#define MEMCPY(_d,_s,_l)	memcpy((_d), (_s), (_l))

static inline void poly1305_blocks(struct poly1305_ctx_s *st,
                                   const uint8_t *m,
                                   unsigned bytes,
                                   const uint32_t hibit);

/******************************************************************************
 *	32 bits env
 ******************************************************************************/
static inline uint32_t
U8TO32_LE(const uint8_t *src)
{
#if 1
        return *((const uint32_t *) src);
#else
        return (((uint32_t) (src[0]) <<  0) |
                ((uint32_t) (src[1]) <<  8) |
                ((uint32_t) (src[2]) << 16) |
                ((uint32_t) (src[3]) << 24));
#endif
}

static inline void
U32TO8_LE(uint8_t *dst,
          uint32_t src)
{
#if 1
        *((uint32_t *) dst) = src;
#else
        dst[0] = (src >>  0) & 0xff;
        dst[1] = (src >>  8) & 0xff;
        dst[2] = (src >> 16) & 0xff;
        dst[3] = (src >> 24) & 0xff;
#endif
}

static inline void
poly1305_init_32(const struct poly1305_key_s *key,
                 struct poly1305_ctx_s *st)
{
        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
        st->r32[0] = (U8TO32_LE(&key->val[ 0])     ) & UINT32_C(0x3ffffff);
        st->r32[1] = (U8TO32_LE(&key->val[ 3]) >> 2) & UINT32_C(0x3ffff03);
        st->r32[2] = (U8TO32_LE(&key->val[ 6]) >> 4) & UINT32_C(0x3ffc0ff);
        st->r32[3] = (U8TO32_LE(&key->val[ 9]) >> 6) & UINT32_C(0x3f03fff);
        st->r32[4] = (U8TO32_LE(&key->val[12]) >> 8) & UINT32_C(0x00fffff);

        /* h = 0 */
        st->h32[0] = 0;
        st->h32[1] = 0;
        st->h32[2] = 0;
        st->h32[3] = 0;
        st->h32[4] = 0;

        /* save pad for later */
        st->pad32[0] = U8TO32_LE(&key->val[16]);
        st->pad32[1] = U8TO32_LE(&key->val[20]);
        st->pad32[2] = U8TO32_LE(&key->val[24]);
        st->pad32[3] = U8TO32_LE(&key->val[28]);

        st->leftover = 0;
}

#define HIBIT_CONTINUE	(1u << 24)
#define HIBIT_FINAL	0

static inline void
poly1305_blocks_32(struct poly1305_ctx_s *st,
                   const uint8_t *m,
                   unsigned bytes,
                   const uint32_t hibit)
{
        uint32_t r[5];
        uint32_t h[5];
        uint32_t s[5];	/* s[0]: unused */
        uint32_t c;
        uint64_t d[5];

        r[0] = st->r32[0];
        r[1] = st->r32[1];
        r[2] = st->r32[2];
        r[3] = st->r32[3];
        r[4] = st->r32[4];

        //        s[0] = r[0] * 5;	/* dummy */
        s[1] = r[1] * 5;
        s[2] = r[2] * 5;
        s[3] = r[3] * 5;
        s[4] = r[4] * 5;

        h[0] = st->h32[0];
        h[1] = st->h32[1];
        h[2] = st->h32[2];
        h[3] = st->h32[3];
        h[4] = st->h32[4];

        while (bytes >= POLY1305_BLOCK_SIZE) {
                /* h += m[i] */
                h[0] += (U8TO32_LE(m + 0)     ) & UINT32_C(0x3ffffff);
                h[1] += (U8TO32_LE(m + 3) >> 2) & UINT32_C(0x3ffffff);
                h[2] += (U8TO32_LE(m + 6) >> 4) & UINT32_C(0x3ffffff);
                h[3] += (U8TO32_LE(m + 9) >> 6) & UINT32_C(0x3ffffff);
                h[4] += (U8TO32_LE(m +12) >> 8) | hibit;

                /* h *= r */
                d[0] = ((uint64_t) h[0] * r[0]) +
                       ((uint64_t) h[1] * s[4]) +
                       ((uint64_t) h[2] * s[3]) +
                       ((uint64_t) h[3] * s[2]) +
                       ((uint64_t) h[4] * s[1]);

                d[1] = ((uint64_t) h[0] * r[1]) +
                       ((uint64_t) h[1] * r[0]) +
                       ((uint64_t) h[2] * s[4]) +
                       ((uint64_t) h[3] * s[3]) +
                       ((uint64_t) h[4] * s[2]);

                d[2] = ((uint64_t) h[0] * r[2]) +
                       ((uint64_t) h[1] * r[1]) +
                       ((uint64_t) h[2] * r[0]) +
                       ((uint64_t) h[3] * s[4]) +
                       ((uint64_t) h[4] * s[3]);

                d[3] = ((uint64_t) h[0] * r[3]) +
                       ((uint64_t) h[1] * r[2]) +
                       ((uint64_t) h[2] * r[1]) +
                       ((uint64_t) h[3] * r[0]) +
                       ((uint64_t) h[4] * s[4]);

                d[4] = ((uint64_t) h[0] * r[4]) +
                       ((uint64_t) h[1] * r[3]) +
                       ((uint64_t) h[2] * r[2]) +
                       ((uint64_t) h[3] * r[1]) +
                       ((uint64_t) h[4] * r[0]);

                /* (partial) h %= p */
                c = (uint32_t) (d[0] >> 26); h[0] = (uint32_t) d[0] & UINT32_C(0x3ffffff);
                d[1] += c;      c = (uint32_t) (d[1] >> 26); h[1] = (uint32_t) d[1] & UINT32_C(0x3ffffff);
                d[2] += c;      c = (uint32_t) (d[2] >> 26); h[2] = (uint32_t) d[2] & UINT32_C(0x3ffffff);
                d[3] += c;      c = (uint32_t) (d[3] >> 26); h[3] = (uint32_t) d[3] & UINT32_C(0x3ffffff);
                d[4] += c;      c = (uint32_t) (d[4] >> 26); h[4] = (uint32_t) d[4] & UINT32_C(0x3ffffff);
                h[0] += c * 5;  c =            (h[0] >> 26); h[0] =            h[0] & UINT32_C(0x3ffffff);
                h[1] += c;

                m     += POLY1305_BLOCK_SIZE;
                bytes -= POLY1305_BLOCK_SIZE;
        }

        st->h32[0] = h[0];
        st->h32[1] = h[1];
        st->h32[2] = h[2];
        st->h32[3] = h[3];
        st->h32[4] = h[4];
}

static inline void
poly1305_finish_32(struct poly1305_ctx_s *st,
                   uint8_t *mac)
{
        uint32_t h[5];
        uint32_t g[5];
        uint32_t c, mask;
        uint64_t f;

        /* process the remaining block */
        if (st->leftover) {
                unsigned i = st->leftover;

                st->buffer[i++] = 1;
                for (; i < POLY1305_BLOCK_SIZE; i++)
                        st->buffer[i] = 0;

                poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE, HIBIT_FINAL);
        }

        /* fully carry h */
        h[0] = st->h32[0];
        h[1] = st->h32[1];
        h[2] = st->h32[2];
        h[3] = st->h32[3];
        h[4] = st->h32[4];

                       c = h[1] >> 26; h[1] = h[1] & UINT32_C(0x3ffffff);
        h[2] +=     c; c = h[2] >> 26; h[2] = h[2] & UINT32_C(0x3ffffff);
        h[3] +=     c; c = h[3] >> 26; h[3] = h[3] & UINT32_C(0x3ffffff);
        h[4] +=     c; c = h[4] >> 26; h[4] = h[4] & UINT32_C(0x3ffffff);
        h[0] += c * 5; c = h[0] >> 26; h[0] = h[0] & UINT32_C(0x3ffffff);
        h[1] +=     c;

        /* compute h + -p */
        g[0] = h[0] + 5; c = g[0] >> 26; g[0] &= UINT32_C(0x3ffffff);
        g[1] = h[1] + c; c = g[1] >> 26; g[1] &= UINT32_C(0x3ffffff);
        g[2] = h[2] + c; c = g[2] >> 26; g[2] &= UINT32_C(0x3ffffff);
        g[3] = h[3] + c; c = g[3] >> 26; g[3] &= UINT32_C(0x3ffffff);
        g[4] = h[4] + c - (1 << 26);

        /* select h if h < p, or h + -p if h >= p */
        mask = (g[4] >> ((sizeof(uint32_t) * 8) - 1)) - 1;
        g[0] &= mask;
        g[1] &= mask;
        g[2] &= mask;
        g[3] &= mask;
        g[4] &= mask;
        mask = ~mask;
        h[0] = (h[0] & mask) | g[0];
        h[1] = (h[1] & mask) | g[1];
        h[2] = (h[2] & mask) | g[2];
        h[3] = (h[3] & mask) | g[3];
        h[4] = (h[4] & mask) | g[4];

        /* h = h % (2^128) */
        h[0] = ((h[0]      ) | (h[1] << 26)) & UINT32_C(0xffffffff);
        h[1] = ((h[1] >>  6) | (h[2] << 20)) & UINT32_C(0xffffffff);
        h[2] = ((h[2] >> 12) | (h[3] << 14)) & UINT32_C(0xffffffff);
        h[3] = ((h[3] >> 18) | (h[4] <<  8)) & UINT32_C(0xffffffff);

        /* mac = (h + pad) % (2^128) */
        f = (uint64_t) h[0] + st->pad32[0]            ; h[0] = (uint32_t) f;
        f = (uint64_t) h[1] + st->pad32[1] + (f >> 32); h[1] = (uint32_t) f;
        f = (uint64_t) h[2] + st->pad32[2] + (f >> 32); h[2] = (uint32_t) f;
        f = (uint64_t) h[3] + st->pad32[3] + (f >> 32); h[3] = (uint32_t) f;

        U32TO8_LE(mac +  0, h[0]);
        U32TO8_LE(mac +  4, h[1]);
        U32TO8_LE(mac +  8, h[2]);
        U32TO8_LE(mac + 12, h[3]);
}

/******************************************************************************
 *	64 bits env
 ******************************************************************************/
#if 0
static inline uint64_t
U8TO64_LE(const uint8_t *src)
{
#if 1
        return *((const uint64_t *) src);
#else
        return (((uint64_t) (src[0]) <<  0) |
                ((uint64_t) (src[1]) <<  8) |
                ((uint64_t) (src[2]) << 16) |
                ((uint64_t) (src[3]) << 24) |
                ((uint64_t) (src[4]) << 32) |
                ((uint64_t) (src[5]) << 40) |
                ((uint64_t) (src[6]) << 48) |
                ((uint64_t) (src[7]) << 56));
#endif
}

static inline void
U64TO8_LE(uint8_t *dst,
          uint64_t src)
{
#if 1
        *((uint64_t *) dst) = src;
#else
        dst[0] = (src >>  0) & 0xff;
        dst[1] = (src >>  8) & 0xff;
        dst[2] = (src >> 16) & 0xff;
        dst[3] = (src >> 24) & 0xff;
        dst[4] = (src >> 32) & 0xff;
        dst[5] = (src >> 40) & 0xff;
        dst[6] = (src >> 48) & 0xff;
        dst[7] = (src >> 56) & 0xff;
#endif
}

static inline void
poly1305_init_64(const struct poly1305_key_s *key,
                 struct poly1305_ctx_s *st)
{
}

static inline void
poly1305_blocks_64(struct poly1305_ctx_s *st,
                   const uint8_t *m,
                   unsigned bytes,
                   const uint32_t hibit)
{

}

static inline void
poly1305_finish_64(struct poly1305_ctx_s *st,
                   uint8_t *mac)

{

}
#endif
/******************************************************************************
 *
 ******************************************************************************/
static inline void
poly1305_blocks(struct poly1305_ctx_s *st,
                   const uint8_t *m,
                   unsigned bytes,
                   const uint32_t hibit)
{
        poly1305_blocks_32(st, m, bytes, hibit);
}


/******************************************************************************
 *	API
 ******************************************************************************/
void
poly1305_update(struct poly1305_ctx_s *st,
                const uint8_t *m,
                unsigned bytes)
{
        unsigned i;

        HEXDUMP("poly1305_update", m, bytes);

        /* handle leftover */
        if (st->leftover) {
                unsigned want = (POLY1305_BLOCK_SIZE - st->leftover);

                if (want > bytes)
                        want = bytes;
                for (i = 0; i < want; i++)
                        st->buffer[st->leftover + i] = m[i];
                bytes -= want;
                m += want;
                st->leftover += want;
                if (st->leftover < POLY1305_BLOCK_SIZE)
                        return;
                poly1305_blocks(st, st->buffer, POLY1305_BLOCK_SIZE, HIBIT_CONTINUE);
                st->leftover = 0;
        }

        /* process full blocks */
        if (bytes >= POLY1305_BLOCK_SIZE) {
                unsigned want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));

                poly1305_blocks(st, m, want, HIBIT_CONTINUE);
                m += want;
                bytes -= want;
        }

        /* store leftover */
        if (bytes) {
                MEMCPY(st->buffer + st->leftover, m, bytes);
                st->leftover += bytes;
        }
}

void
poly1305_init(const struct poly1305_key_s *key,
                 struct poly1305_ctx_s *st)
{
        poly1305_init_32(key, st);
}

void
poly1305_finish(struct poly1305_ctx_s *st,
                uint8_t *mac)
{
        poly1305_finish_32(st, mac);
}

void
poly1305(const struct poly1305_key_s *key,
         uint8_t *mac,
         const uint8_t *m,
         unsigned bytes)
{
        struct poly1305_ctx_s ctx __attribute__((aligned(64)));

        poly1305_init(key, &ctx);
        poly1305_update(&ctx, m, bytes);
        poly1305_finish(&ctx, mac);
}
