/* $OpenBSD: chacha.h,v 1.4 2016/08/27 04:04:56 guenther Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#define CHACHA_KEYLEN 	        32
#define CHACHA_NONCELEN		12
#define CHACHA_CTRLEN		4
#define CHACHA_STATELEN		(CHACHA_NONCELEN + CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

static inline void
dump_state(const char *msg,
           const uint32_t *state)
{
        fprintf(stderr, "%s\n", msg);
        for (unsigned i = 0; i < 16; i += 4) {
                fprintf(stderr, "0x%08x 0x%08x 0x%08x 0x%08x\n",
                        state[i + 0],
                        state[i + 1],
                        state[i + 2],
                        state[i + 3]);
        }
}

static inline void
hexdump(const char *msg,
        const void *p,
        size_t len)
{
        unsigned int i, out, ofs;
        const unsigned char *data = p;

        fprintf(stderr, "%s\n", msg);

        ofs = 0;
        while (ofs < len) {
                char line[120];

                out = snprintf(line, sizeof(line), "%08x:", ofs);
                for (i = 0; ((ofs + i) < len) && (i < 16); i++)
                        out += snprintf(line + out, sizeof(line) - out,
                                        " %02x", (data[ofs + i] & 0xff));
                for(; i <= 16; i++)
                        out += snprintf(line + out, sizeof(line) - out, " | ");
                for(i = 0; (ofs < len) && (i < 16); i++, ofs++) {
                        unsigned char c = data[ofs];

                        if ( (c < ' ') || (c > '~'))
                                c = '.';
                        out += snprintf(line + out, sizeof(line) - out, "%c", c);
                }
                fprintf(stderr, "%s\n", line);
        }
}


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


#endif	/* CHACHA_H */

