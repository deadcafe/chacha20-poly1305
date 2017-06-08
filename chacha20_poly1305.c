
#include <string.h>

#include "chacha20_poly1305.h"
#include "tools.h"

static void
init_poly1305(struct chacha20_poly1305_ctx *ctx)
{
        const uint8_t zero[POLY1305_KEYLEN] = { 0 };
        uint8_t key[POLY1305_KEYLEN];

        chacha20_block(key, zero, sizeof(key), ctx->chacha20_state);
        hexdump("poly key", key, sizeof(key));
        poly1305_init(&ctx->poly1305_state, key);
}

int
aead_chacha20_poly1305(const uint8_t key[CHACHA_KEYLEN],
                       enum cipher_direction_e dir,
                       const uint8_t nonce[CHACHA_NONCELEN],
                       uint8_t *out,
                       const uint8_t *in,
                       unsigned inlen,
                       const uint8_t *aad,
                       unsigned aad_len,
                       uint8_t tag[POLY1305_TAGLEN])
{
        struct chacha20_poly1305_ctx ctx __attribute__((aligned(64)));
        struct {
                uint64_t aad_octets;
                uint64_t ciphertext_octets;
        } length;

        if (dir != CIPHER_DIR_ENCRYPT)
                return -1;

        hexdump("key", key, CHACHA_KEYLEN);
        hexdump("nonce", nonce, CHACHA_NONCELEN);
        hexdump("in", in, inlen);
        hexdump("aad", aad, aad_len);

        length.aad_octets = aad_len;
        length.ciphertext_octets = inlen;

        chacha20_init(ctx.chacha20_state,
                      key,
                      nonce,
                      0);

        hexdump("after chacha init",
                ctx.chacha20_state, sizeof(ctx.chacha20_state));

        init_poly1305(&ctx);
        hexdump("after poly init",
                &ctx.poly1305_state, sizeof(ctx.poly1305_state));

        if (aad_len >= POLY1305_BLOCK_SIZE) {
                poly1305_update(&ctx.poly1305_state,
                                aad,
                                aad_len & ~(POLY1305_BLOCK_SIZE - 1));

                aad += aad_len & ~(POLY1305_BLOCK_SIZE - 1);
                aad_len &= (POLY1305_BLOCK_SIZE - 1);
        }
        if (aad_len) {
                uint8_t pad[POLY1305_BLOCK_SIZE];

                memcpy(pad, aad, aad_len);
                for (unsigned i = aad_len; i < POLY1305_BLOCK_SIZE; i++)
                        pad[i] = 0;
                poly1305_update(&ctx.poly1305_state, pad, sizeof(pad));
        }

        while (inlen >= CHACHA_BLOCKLEN) {
                unsigned len = CHACHA_BLOCKLEN;

                chacha20_block(out, in, CHACHA_BLOCKLEN, ctx.chacha20_state);

                do {
                        poly1305_update(&ctx.poly1305_state, out,
                                        POLY1305_BLOCK_SIZE);
                        out += POLY1305_BLOCK_SIZE;
                        len -= POLY1305_BLOCK_SIZE;
                } while (len);

                in += CHACHA_BLOCKLEN;
                inlen -= CHACHA_BLOCKLEN;
        }

        if (inlen) {

                chacha20_block(out, in, inlen, ctx.chacha20_state);
                while (inlen >= POLY1305_BLOCK_SIZE) {
                        poly1305_update(&ctx.poly1305_state,
                                        out,
                                        POLY1305_BLOCK_SIZE);
                        out += POLY1305_BLOCK_SIZE;
                        inlen -= POLY1305_BLOCK_SIZE;
                }

                if (inlen) {
                        uint8_t pad[POLY1305_BLOCK_SIZE];

                        memcpy(pad, out, inlen);
                        for (unsigned i = inlen; i < POLY1305_BLOCK_SIZE; i++)
                                pad[i] = 0;
                        poly1305_update(&ctx.poly1305_state, pad, sizeof(pad));
                }
        }

        poly1305_update(&ctx.poly1305_state,
                        (const uint8_t *) &length, sizeof(length));
        poly1305_finish(&ctx.poly1305_state, tag);
        return 0;
}
