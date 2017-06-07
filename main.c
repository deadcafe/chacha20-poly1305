
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "chacha.h"
#include "poly1305.h"

struct test_vector_s {
        /* key */
        const uint8_t *K;
        size_t         Klen;

        /* nonce */
        const uint8_t *N;
        size_t         Nlen;

        /* text */
        const uint8_t *P;
        const uint8_t *C;
        size_t Plen;

        /* tag */
        const uint8_t *T;
        size_t Tlen;

};


static const uint8_t Key_chacha[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t Nonce_chacha[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
};

static const uint8_t Plain_chacha[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
#if 0
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
#endif
};

static const uint8_t Cipher_chacha[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
#if 0
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
#endif
};

static const uint8_t Tag_chacha[] = {};


/*
 * Poly
 */
static const uint8_t Key_poly[] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
};

static const uint8_t Nonce_poly[] = {
};

static const uint8_t Plain_poly[] = {
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
        0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
        0x75, 0x70,
};

static const uint8_t Cipher_poly[] = {
};

static const uint8_t Tag_poly[] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
};





#define VECTOR(X)                                               \
        {                                                       \
                Key_##X,sizeof(Key_##X),                        \
                (Nonce_##X),sizeof(Nonce_##X),                  \
                Plain_##X,Cipher_##X,sizeof(Plain_##X),         \
                Tag_##X,sizeof(Tag_##X),                        \
        }


static const struct test_vector_s test_vectores[] = {
        VECTOR(chacha),
        VECTOR(poly),
};


static void
test_chacha(const struct test_vector_s *vec)
{
        uint8_t cipher[vec->Plen];
        uint8_t plain[vec->Plen];

        memset(cipher, 0, sizeof(cipher));

        chacha20(cipher, vec->P, vec->Plen, vec->K, vec->N, 1);
        chacha20(plain,  cipher, vec->Plen, vec->K, vec->N, 1);

        if (memcmp(plain, vec->P, vec->Plen)) {
                fprintf(stderr, "failed decryption\n");

                hexdump("Plain",   vec->P, vec->Plen);
                hexdump("decrypt", plain, vec->Plen);
        } else {
                fprintf(stderr, "success decryption\n");
        }

        if (memcmp(cipher, vec->C, vec->Plen)) {
                fprintf(stderr, "mismatched\n");

                hexdump("Target", cipher, vec->Plen);
                hexdump("Cipher", vec->C, vec->Plen);
                hexdump("Plain",  vec->P, vec->Plen);
        } else
                fprintf(stderr, "matched\n");
}

static void
test_poly(const struct test_vector_s *vec)
{
        uint8_t mac[16];

        poly1305(mac, vec->P, vec->Plen, vec->K);

        if (memcmp(mac, vec->T, 16))
                fprintf(stderr, "poly: mismatched\n");
        else
                fprintf(stderr, "poly: matched\n");

        hexdump("Mac", mac, 16);
}

struct chacha20_poly1305_ctx {
        uint32_t chacha20_state[16];
        struct poly1305_state_s poly1305_state;
};

static void
init_poly1305(struct chacha20_poly1305_ctx *ctx)
{
        const uint8_t zero[POLY1305_KEYLEN] = { 0 };
        uint8_t key[POLY1305_KEYLEN];

        chacha20_block(key, zero, sizeof(key), ctx->chacha20_state);
        poly1305_init(&ctx->poly1305_state, key);
}

void
chacha20_poly1305_enc(const uint8_t key[CHACHA_KEYLEN],
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

        length.aad_octets = aad_len;
        length.ciphertext_octets = inlen;

        chacha20_init(ctx.chacha20_state,
                      key,
                      nonce,
                      0);
        init_poly1305(&ctx);

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
                uint8_t pad[POLY1305_BLOCK_SIZE];

                chacha20_block(out, in, inlen, ctx.chacha20_state);
                for (unsigned i = inlen; i < POLY1305_BLOCK_SIZE; i++)
                        pad[i] = 0;
                poly1305_update(&ctx.poly1305_state, pad, sizeof(pad));
        }
        poly1305_update(&ctx.poly1305_state,
                        (const uint8_t *) &length, sizeof(length));
        poly1305_finish(&ctx.poly1305_state, tag);
}

int
main(void)
{
        test_chacha(&test_vectores[0]);
        test_poly(&test_vectores[1]);

        return 0;
}
