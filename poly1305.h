/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/*
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ifndef POLY1305_H
#define POLY1305_H

#include <sys/types.h>
#include <stdint.h>

#define POLY1305_KEYLEN		32
#define POLY1305_TAGLEN		16
#define POLY1305_BLOCK_SIZE	16

struct poly1305_state_s {
        uint32_t r[5];
        uint32_t h[5];
        uint32_t pad[4];
        unsigned final;
        unsigned leftover;
        uint8_t buffer[POLY1305_BLOCK_SIZE];
};

extern void poly1305_init(struct poly1305_state_s *st,
                          const uint8_t key[POLY1305_KEYLEN]);
extern void poly1305_update(struct poly1305_state_s *st,
                            const uint8_t *m,
                            unsigned bytes);
extern void poly1305_finish(struct poly1305_state_s *st,
                            unsigned char mac[POLY1305_TAGLEN]);

/* one-shot */
extern void poly1305(uint8_t mac[POLY1305_TAGLEN],
                     const uint8_t *m,
                     unsigned bytes,
                     const uint8_t key[POLY1305_KEYLEN]);
#endif	/* POLY1305_H */
