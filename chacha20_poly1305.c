
#include <string.h>

#include "chacha20_poly1305.h"
#include "tools.h"

struct chacha20_poly1305_ctx_s {
        struct chacha20_ctx_s chacha20;
        struct poly1305_ctx_s poly1305;
};

static inline void
chacha20_poly1305_init(const struct chacha20_key_s *chacha20_key,
                       struct chacha20_poly1305_ctx_s *ctx,
                       const uint8_t *nonce)
{
        const uint8_t zero[POLY1305_KEYLEN] = { 0 };
        struct poly1305_key_s poly1305_key __attribute__((aligned(16)));

        chacha20_init(chacha20_key, &ctx->chacha20, nonce, 0);
        HEXDUMP("after chacha init", &ctx->chacha20, sizeof(ctx->chacha20));

        chacha20_block(&ctx->chacha20, poly1305_key.val, zero, sizeof(zero));
        HEXDUMP("poly key", poly1305_key.val, sizeof(poly1305_key.val));

        poly1305_init(&poly1305_key, &ctx->poly1305);
        HEXDUMP("poly state", &ctx->poly1305, sizeof(ctx->poly1305));
}

static inline unsigned
poly1305_with_pad(struct poly1305_ctx_s *ctx,
                  const uint8_t *in,
                  unsigned inlen)
{
        unsigned len = inlen;

        while (len >= POLY1305_BLOCK_SIZE) {
                poly1305_update(ctx, in, POLY1305_BLOCK_SIZE);
                in  += POLY1305_BLOCK_SIZE;
                len -= POLY1305_BLOCK_SIZE;
        }

        if (len) {
                uint8_t pad[POLY1305_BLOCK_SIZE];

                memcpy(pad, in, len);
                for (unsigned i = len; i < POLY1305_BLOCK_SIZE; i++)
                        pad[i] = 0;
                poly1305_update(ctx, pad, sizeof(pad));
        }
        return inlen;
}

int
aead_chacha20_poly1305_enc(const struct chacha20_key_s *chacha20_key,
                           const uint8_t *nonce,
                           uint8_t *out,
                           const uint8_t *in,
                           unsigned inlen,
                           const uint8_t *aad,
                           unsigned aad_len,
                           uint8_t *tag)
{
        struct chacha20_poly1305_ctx_s ctx __attribute__((aligned(16)));
        struct {
                uint64_t aad_octets;
                uint64_t ciphertext_octets;
        } length __attribute__((aligned(16)));

        HEXDUMP("key", chacha20_key->val, CHACHA_KEYLEN);
        HEXDUMP("nonce", nonce, CHACHA_NONCELEN);
        HEXDUMP("in", in, inlen);
        HEXDUMP("aad", aad, aad_len);

        length.aad_octets = aad_len;
        length.ciphertext_octets = inlen;

        chacha20_poly1305_init(chacha20_key, &ctx, nonce);

        poly1305_with_pad(&ctx.poly1305, aad, aad_len);

        while (inlen >= CHACHA_BLOCKLEN) {
                chacha20_block(&ctx.chacha20, out, in, CHACHA_BLOCKLEN);
                poly1305_with_pad(&ctx.poly1305, out, CHACHA_BLOCKLEN);

                in    += CHACHA_BLOCKLEN;
                out   += CHACHA_BLOCKLEN;
                inlen -= CHACHA_BLOCKLEN;
        }

        if (inlen) {
                chacha20_block(&ctx.chacha20, out, in, inlen);
                poly1305_with_pad(&ctx.poly1305, out, inlen);
        }

        poly1305_update(&ctx.poly1305, (const uint8_t *) &length, sizeof(length));
        poly1305_finish(&ctx.poly1305, tag);
        return 0;
}

int
aead_chacha20_poly1305_dec(const struct chacha20_key_s *chacha20_key,
                           const uint8_t *nonce,
                           uint8_t *out,
                           const uint8_t *in,
                           unsigned inlen,
                           const uint8_t *aad,
                           unsigned aad_len,
                           const uint8_t *enc_tag)
{
        struct chacha20_poly1305_ctx_s ctx __attribute__((aligned(16)));
        uint8_t tag[POLY1305_TAGLEN] __attribute__((aligned(16)));
        struct {
                uint64_t aad_octets;
                uint64_t ciphertext_octets;
        } length __attribute__((aligned(16)));

        length.aad_octets = aad_len;
        length.ciphertext_octets = inlen;

        chacha20_poly1305_init(chacha20_key, &ctx, nonce);

        poly1305_with_pad(&ctx.poly1305, aad, aad_len);

        while (inlen >= CHACHA_BLOCKLEN) {
                poly1305_with_pad(&ctx.poly1305, in, CHACHA_BLOCKLEN);
                chacha20_block(&ctx.chacha20, out, in, CHACHA_BLOCKLEN);

                in    += CHACHA_BLOCKLEN;
                out   += CHACHA_BLOCKLEN;
                inlen -= CHACHA_BLOCKLEN;
        }

        if (inlen) {
                poly1305_with_pad(&ctx.poly1305, in, inlen);
                chacha20_block(&ctx.chacha20, out, in, inlen);
        }

        poly1305_update(&ctx.poly1305, (const uint8_t *) &length, sizeof(length));
        poly1305_finish(&ctx.poly1305, tag);

        return memcmp(tag, enc_tag, sizeof(tag));
}
