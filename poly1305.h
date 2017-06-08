#ifndef POLY1305_H
#define POLY1305_H

#include <sys/types.h>
#include <stdint.h>

#define POLY1305_KEYLEN		32
#define POLY1305_TAGLEN		16
#define POLY1305_BLOCK_SIZE	16

struct poly1305_key_s {
        uint8_t val[POLY1305_KEYLEN];
};

struct poly1305_ctx_s {
        uint32_t r[5];
        uint32_t h[5];
        uint32_t pad[4];
        unsigned final;
        unsigned leftover;
        uint8_t buffer[POLY1305_BLOCK_SIZE];
};

extern void poly1305_init(const struct poly1305_key_s *key,
                          struct poly1305_ctx_s *st);

extern void poly1305_update(struct poly1305_ctx_s *st,
                            const uint8_t *m,
                            unsigned bytes);

extern void poly1305_finish(struct poly1305_ctx_s *st,
                            unsigned char mac[POLY1305_TAGLEN]);

/* one-shot */
extern void poly1305(const struct poly1305_key_s *key,
                     uint8_t mac[POLY1305_TAGLEN],
                     const uint8_t *m,
                     unsigned bytes);

#endif	/* POLY1305_H */
