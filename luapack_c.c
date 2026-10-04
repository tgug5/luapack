/*
 * luapack_c.c  —  luapack 加密容器 C 运行时解密库（自包含实现）
 *
 * 与 luapack.py 的输出逐字节互通：
 *   SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256(200000) / AES-256-CBC / XXTEA-128
 */

#include "luapack_c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================= 基础常量 ========================= */
#define LPK_MAGIC0      'L'
#define LPK_MAGIC1      'P'
#define LPK_MAGIC2      'K'
#define LPK_MAGIC3      0x01

#define CIPHER_XTEA     0
#define CIPHER_AES      1
#define CIPHER_NONE     2

#define FLAG_SCRAMBLE   0x01
#define FLAG_HMAC       0x02
#define FLAG_KDF_STRONG 0x04

#define PBKDF2_ROUNDS   200000u
#define SCRAMBLE_LEN    32
#define NONCE_LEN       16

static const char PLAIN_MAGIC[4] = { 'L', 'P', 'B', 'C' };

/* ========================= SHA-256 ========================= */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)     (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define BSIG1(x)     (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SSIG0(x)     (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SSIG1(x)     (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_init(sha256_ctx *c)
{
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->bitlen = 0;
    c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++)
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + BSIG1(e) + CH(e, f, g) + SHA256_K[i] + w[i];
        t2 = BSIG0(a) + MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
    size_t i = 0;
    c->bitlen += (uint64_t)len * 8;
    while (i < len) {
        size_t take = 64 - c->buflen;
        if (take > len - i) take = len - i;
        memcpy(c->buf + c->buflen, data + i, take);
        c->buflen += take;
        i += take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint8_t pad[72];
    size_t padlen;
    uint64_t bl = c->bitlen;
    int i;

    pad[0] = 0x80;
    padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
    memset(pad + 1, 0, padlen - 1);
    for (i = 0; i < 8; i++)
        pad[padlen + i] = (uint8_t)(bl >> (56 - i * 8));
    sha256_update(c, pad, padlen + 8);

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

/* ====================== HMAC-SHA256 ====================== */
static void hmac_sha256(const uint8_t *key, size_t keylen,
                        const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[32];
    sha256_ctx c;
    size_t i;

    memset(k, 0, 64);
    if (keylen > 64) {
        sha256(key, keylen, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

/* ================== PBKDF2-HMAC-SHA256 ================== */
static void pbkdf2_sha256(const uint8_t *pw, size_t pwlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t iters, uint8_t *out, size_t outlen)
{
    uint32_t block = 1;
    size_t done = 0;
    uint8_t *saltblk = (uint8_t *)malloc(saltlen + 4);
    if (!saltblk) return;
    memcpy(saltblk, salt, saltlen);

    while (done < outlen) {
        uint8_t u[32], t[32];
        uint32_t i, j;
        saltblk[saltlen]     = (uint8_t)(block >> 24);
        saltblk[saltlen + 1] = (uint8_t)(block >> 16);
        saltblk[saltlen + 2] = (uint8_t)(block >> 8);
        saltblk[saltlen + 3] = (uint8_t)(block);

        hmac_sha256(pw, pwlen, saltblk, saltlen + 4, u);
        memcpy(t, u, 32);
        for (i = 1; i < iters; i++) {
            hmac_sha256(pw, pwlen, u, 32, u);
            for (j = 0; j < 32; j++) t[j] ^= u[j];
        }
        {
            size_t take = outlen - done;
            if (take > 32) take = 32;
            memcpy(out + done, t, take);
            done += take;
        }
        block++;
    }
    free(saltblk);
}

/* ================== AES-256-CBC 解密 ================== */
static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static int aes_inited = 0;
static uint8_t AES_INV_SBOX[256];
static uint8_t AES_RCON[15];

static uint8_t aes_xt(uint8_t a) { return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00)); }

static uint8_t aes_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        b >>= 1;
        a = aes_xt(a);
    }
    return p;
}

static void aes_init_tables(void)
{
    int i;
    if (aes_inited) return;
    for (i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = (uint8_t)i;
    AES_RCON[0] = 0x01;
    for (i = 1; i < 15; i++) {
        uint8_t v = AES_RCON[i - 1];
        AES_RCON[i] = (uint8_t)((v << 1) ^ ((v & 0x80) ? 0x1b : 0x00));
    }
    aes_inited = 1;
}

/* AES-256: Nk=8, Nr=14 -> round key 4*(14+1)=60 words */
static void aes256_expand(const uint8_t key[32], uint32_t rk[60])
{
    int i;
    for (i = 0; i < 8; i++)
        rk[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
                ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];

    for (i = 8; i < 60; i++) {
        uint32_t t = rk[i - 1];
        if (i % 8 == 0) {
            t = (t << 8) | (t >> 24);                       /* RotWord */
            t = ((uint32_t)AES_SBOX[(t >> 24) & 0xff] << 24) |
                ((uint32_t)AES_SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)AES_SBOX[(t >> 8) & 0xff] << 8) |
                ((uint32_t)AES_SBOX[t & 0xff]);
            t ^= (uint32_t)AES_RCON[i / 8 - 1] << 24;
        } else if (i % 8 == 4) {
            t = ((uint32_t)AES_SBOX[(t >> 24) & 0xff] << 24) |
                ((uint32_t)AES_SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)AES_SBOX[(t >> 8) & 0xff] << 8) |
                ((uint32_t)AES_SBOX[t & 0xff]);
        }
        rk[i] = rk[i - 8] ^ t;
    }
}

static void aes256_decrypt_block(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16])
{
    uint8_t st[16];
    int r, c, round;

    memcpy(st, in, 16);

#define ADD_RK(rn)                                                              \
    do {                                                                        \
        for (c = 0; c < 4; c++) {                                               \
            uint32_t w = rk[(rn) * 4 + c];                                      \
            st[0 + 4 * c] ^= (uint8_t)(w >> 24);                                \
            st[1 + 4 * c] ^= (uint8_t)(w >> 16);                                \
            st[2 + 4 * c] ^= (uint8_t)(w >> 8);                                 \
            st[3 + 4 * c] ^= (uint8_t)(w);                                      \
        }                                                                       \
    } while (0)

    ADD_RK(14);

    for (round = 13; round >= 1; round--) {
        /* InvShiftRows: row r 右移 r */
        for (r = 1; r < 4; r++) {
            uint8_t tmp[4];
            for (c = 0; c < 4; c++) tmp[(c + r) % 4] = st[r + 4 * c];
            for (c = 0; c < 4; c++) st[r + 4 * c] = tmp[c];
        }
        /* InvSubBytes */
        for (r = 0; r < 16; r++) st[r] = AES_INV_SBOX[st[r]];
        ADD_RK(round);
        /* InvMixColumns */
        for (c = 0; c < 4; c++) {
            uint8_t a0 = st[0 + 4 * c], a1 = st[1 + 4 * c];
            uint8_t a2 = st[2 + 4 * c], a3 = st[3 + 4 * c];
            st[0 + 4 * c] = (uint8_t)(aes_mul(a0,14) ^ aes_mul(a1,11) ^ aes_mul(a2,13) ^ aes_mul(a3,9));
            st[1 + 4 * c] = (uint8_t)(aes_mul(a0,9)  ^ aes_mul(a1,14) ^ aes_mul(a2,11) ^ aes_mul(a3,13));
            st[2 + 4 * c] = (uint8_t)(aes_mul(a0,13) ^ aes_mul(a1,9)  ^ aes_mul(a2,14) ^ aes_mul(a3,11));
            st[3 + 4 * c] = (uint8_t)(aes_mul(a0,11) ^ aes_mul(a1,13) ^ aes_mul(a2,9)  ^ aes_mul(a3,14));
        }
    }
    for (r = 1; r < 4; r++) {
        uint8_t tmp[4];
        for (c = 0; c < 4; c++) tmp[(c + r) % 4] = st[r + 4 * c];
        for (c = 0; c < 4; c++) st[r + 4 * c] = tmp[c];
    }
    for (r = 0; r < 16; r++) st[r] = AES_INV_SBOX[st[r]];
    ADD_RK(0);

#undef ADD_RK

    memcpy(out, st, 16);
}

/* CBC 解密 + 去 PKCS#7，返回明文长度，失败返回 -1 */
static long aes256_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16],
                               const uint8_t *in, size_t inlen, uint8_t *out)
{
    uint32_t rk[60];
    uint8_t prev[16];
    size_t off;

    if (inlen == 0 || inlen % 16 != 0) return -1;
    aes_init_tables();
    aes256_expand(key, rk);
    memcpy(prev, iv, 16);

    for (off = 0; off < inlen; off += 16) {
        uint8_t blk[16];
        int i;
        aes256_decrypt_block(rk, in + off, blk);
        for (i = 0; i < 16; i++) out[off + i] = (uint8_t)(blk[i] ^ prev[i]);
        memcpy(prev, in + off, 16);
    }
    {
        uint8_t pad = out[inlen - 1];
        if (pad < 1 || pad > 16) return (long)inlen;
        return (long)(inlen - pad);
    }
}

/* ====================== XXTEA-128 ====================== */
#define XT_DELTA 0x9E3779B9u

static uint32_t xt_mx(uint32_t sum, uint32_t y, uint32_t z, int p, uint32_t e,
                      const uint32_t k[4])
{
    uint32_t a = (z >> 5) ^ (y << 2);
    uint32_t b = (y >> 3) ^ (z << 4);
    uint32_t cc = (sum ^ y) + (k[(p & 3) ^ e] ^ z);
    return (a + b) ^ cc;
}

static void xt_decrypt(uint32_t *v, int n, const uint32_t k[4])
{
    uint32_t rounds, sum, y, e;
    int p, r;
    if (n < 2) return;
    rounds = (uint32_t)(6 + 52 / n);
    sum = rounds * XT_DELTA;
    y = v[0];
    for (r = 0; r < (int)rounds; r++) {
        e = (sum >> 2) & 3u;
        for (p = n - 1; p > 0; p--) {
            uint32_t z = v[p - 1];
            v[p] -= xt_mx(sum, y, z, p, e, k);
            y = v[p];
        }
        {
            uint32_t z = v[n - 1];
            v[0] -= xt_mx(sum, y, z, 0, e, k);
            y = v[0];
        }
        sum -= XT_DELTA;
    }
}

/* ============== 密钥派生 / 头部逆变异 ============== */
static void kdf_lite(const char *password, uint8_t out[32])
{
    static const char tag[] = "luapack-lite-key|";
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)tag, sizeof(tag) - 1);
    sha256_update(&c, (const uint8_t *)password, strlen(password));
    sha256_final(&c, out);
}

static void kdf_strong(const char *password, const uint8_t salt[16], uint8_t out[32])
{
    pbkdf2_sha256((const uint8_t *)password, strlen(password),
                  salt, 16, PBKDF2_ROUNDS, out, 32);
}

static void key_check(const uint8_t key[32], uint8_t out[8])
{
    static const char tag[] = "luapack-keycheck|";
    sha256_ctx c;
    uint8_t h[32];
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)tag, sizeof(tag) - 1);
    sha256_update(&c, key, 32);
    sha256_final(&c, h);
    memcpy(out, h, 8);
}

/* 计数器模式 SHA512 字节流 */
static void stream_bytes(const uint8_t *seed, size_t seedlen, uint8_t *out, size_t need)
{
    /* 这里只需要 SHA256 级别强度即可，用 HMAC-SHA256 做计数器流 */
    size_t done = 0;
    uint32_t ctr = 0;
    while (done < need) {
        uint8_t ctrb[4];
        uint8_t h[32];
        sha256_ctx c;
        ctrb[0] = (uint8_t)(ctr); ctrb[1] = (uint8_t)(ctr >> 8);
        ctrb[2] = (uint8_t)(ctr >> 16); ctrb[3] = (uint8_t)(ctr >> 24);
        sha256_init(&c);
        sha256_update(&c, seed, seedlen);
        sha256_update(&c, ctrb, 4);
        sha256_final(&c, h);
        {
            size_t take = need - done;
            if (take > 32) take = 32;
            memcpy(out + done, h, take);
            done += take;
        }
        ctr++;
    }
}

static void scramble_perm(const uint8_t key[32], int n, int *perm)
{
    static const char tag[] = "luapack-scramble|";
    uint8_t seed[64], stream[SCRAMBLE_LEN * 4];
    int i;
    memcpy(seed, tag, sizeof(tag) - 1);
    memcpy(seed + sizeof(tag) - 1, key, 32);
    for (i = 0; i < n; i++) perm[i] = i;
    if (n <= 1) return;
    stream_bytes(seed, sizeof(tag) - 1 + 32, stream, (size_t)n * 4);
    for (i = n - 1; i > 0; i--) {
        uint32_t v = (uint32_t)stream[i * 4] | ((uint32_t)stream[i * 4 + 1] << 8) |
                     ((uint32_t)stream[i * 4 + 2] << 16) | ((uint32_t)stream[i * 4 + 3] << 24);
        int j = (int)(v % (uint32_t)(i + 1));
        int t = perm[i]; perm[i] = perm[j]; perm[j] = t;
    }
}

static void scramble_mask(const uint8_t key[32], uint8_t out[32])
{
    static const char tag[] = "luapack-mask|";
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)tag, sizeof(tag) - 1);
    sha256_update(&c, key, 32);
    sha256_final(&c, out);
}

static void unscramble_head(uint8_t *data, int n, const uint8_t key[32])
{
    uint8_t mask[32], tmp[SCRAMBLE_LEN];
    int perm[SCRAMBLE_LEN];
    int i, m;
    if (n < 2) return;
    if (n > SCRAMBLE_LEN) n = SCRAMBLE_LEN;
    scramble_perm(key, n, perm);
    scramble_mask(key, mask);
    m = (int)sizeof(mask);
    for (i = 0; i < n; i++) {
        int dst = perm[i];
        tmp[dst] = (uint8_t)(data[i] ^ mask[i % m]);
    }
    memcpy(data, tmp, (size_t)n);
}

/* ============== 小端读 ============== */
static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ========================= API ========================= */
const char *lpk_strerror(int code)
{
    switch (code) {
    case 0:  return "ok";
    case -1: return "invalid argument";
    case -2: return "cannot read file or allocate memory";
    case -3: return "not a luapack container";
    case -4: return "unsupported container version";
    case -5: return "wrong password";
    case -6: return "integrity check failed (tampered)";
    case -7: return "corrupted data or bad length";
    case -8: return "cipher not supported by this build";
    default: return "unknown error";
    }
}

void lpk_free(lpk_buffer *buf)
{
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
    }
}

int lpk_peek(const uint8_t *blob, size_t blob_len, lpk_info_t *info)
{
    uint8_t flags;
    if (!blob || !info || blob_len < LPK_HEADER_SIZE + 8) return -3;
    if (blob[0] != LPK_MAGIC0 || blob[1] != LPK_MAGIC1 ||
        blob[2] != LPK_MAGIC2 || blob[3] != LPK_MAGIC3) return -3;
    if (blob[4] != 1) return -4;

    flags = blob[7];
    info->lua_ver     = blob[5];             /* 1=5.1 2=5.2 3=5.3 4=5.4 */
    info->cipher      = blob[6];
    info->scramble    = (flags & FLAG_SCRAMBLE) ? 1 : 0;
    info->hmac        = (flags & FLAG_HMAC) ? 1 : 0;
    info->strong_kdf  = (flags & FLAG_KDF_STRONG) ? 1 : 0;
    info->bytecode_len = (size_t)rd_u64(blob + 8);
    info->payload_len  = (size_t)rd_u64(blob + 16);
    info->packed_at    = rd_u64(blob + 68);
    return 0;
}

int lpk_decrypt(const uint8_t *blob, size_t blob_len,
                const char *password, lpk_buffer *out)
{
    uint8_t flags, cipher, key[32], kc[8], expect[8];
    size_t payload_len, plain_len;
    const uint8_t *payload;
    uint8_t *body = NULL;
    size_t body_len = 0;
    int scramble, use_hmac, strong;
    int rc = 0;

    if (!blob || !password || !out) return -1;
    out->data = NULL;
    out->len = 0;

    if (blob_len < LPK_HEADER_SIZE + 8) return -3;
    if (blob[0] != LPK_MAGIC0 || blob[1] != LPK_MAGIC1 ||
        blob[2] != LPK_MAGIC2 || blob[3] != LPK_MAGIC3) return -3;
    if (blob[4] != 1) return -4;

    flags     = blob[7];
    cipher    = blob[6];
    scramble  = (flags & FLAG_SCRAMBLE) != 0;
    use_hmac  = (flags & FLAG_HMAC) != 0;
    strong    = (flags & FLAG_KDF_STRONG) != 0;
    plain_len   = (size_t)rd_u64(blob + 8);
    payload_len = (size_t)rd_u64(blob + 16);

    if (LPK_HEADER_SIZE + payload_len > blob_len) return -7;

    if (strong) kdf_strong(password, blob + 24, key);
    else        kdf_lite(password, key);

    key_check(key, expect);
    memcpy(kc, blob + 56, 8);
    if (memcmp(kc, expect, 8) != 0) return -5;

    payload = blob + LPK_HEADER_SIZE;

    if (use_hmac) {
        uint8_t mac[32];
        if (LPK_HEADER_SIZE + payload_len + 32 > blob_len) return -7;
        hmac_sha256(key, 32, blob, LPK_HEADER_SIZE + payload_len, mac);
        if (memcmp(mac, blob + LPK_HEADER_SIZE + payload_len, 32) != 0) return -6;
    }

    if (cipher == CIPHER_XTEA) {
        size_t i, n;
        uint32_t k[4];
        uint32_t *v;
        if (payload_len % 4 != 0 || payload_len < 8) return -7;
        n = payload_len / 4;
        v = (uint32_t *)malloc(payload_len);
        if (!v) return -2;
        for (i = 0; i < n; i++) v[i] = rd_u32(payload + i * 4);
        for (i = 0; i < 4; i++) k[i] = rd_u32(key + i * 4);
        xt_decrypt(v, (int)n, k);
        body = (uint8_t *)v;
        body_len = payload_len;
    } else if (cipher == CIPHER_AES) {
        uint8_t *buf = (uint8_t *)malloc(payload_len ? payload_len : 1);
        long got;
        if (!buf) return -2;
        got = aes256_cbc_decrypt(key, blob + 40, payload, payload_len, buf);
        if (got < 0) { free(buf); return -7; }
        body = buf;
        body_len = (size_t)got;
    } else if (cipher == CIPHER_NONE) {
        body = (uint8_t *)malloc(payload_len ? payload_len : 1);
        if (!body) return -2;
        memcpy(body, payload, payload_len);
        body_len = payload_len;
    } else {
        return -8;
    }

    if (scramble) unscramble_head(body, (int)body_len, key);

    /* 明文结构: "LPBC" + u32 len + nonce(16) + bytecode */
    if (body_len < 24 || memcmp(body, PLAIN_MAGIC, 4) != 0) {
        free(body);
        return -5;
    }
    {
        uint32_t inlen = rd_u32(body + 4);
        if ((size_t)24 + inlen > body_len) { free(body); return -7; }
        if (plain_len != 0 && (size_t)inlen != plain_len) { free(body); return -7; }
        out->data = (uint8_t *)malloc(inlen ? inlen : 1);
        if (!out->data) { free(body); return -2; }
        memcpy(out->data, body + 24, inlen);
        out->len = inlen;
    }
    free(body);
    return rc;
}

static uint8_t *read_whole_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

int lpk_decrypt_file(const char *path, const char *password, lpk_buffer *out)
{
    uint8_t *blob;
    size_t len = 0;
    int rc;
    if (!path || !out) return -1;
    blob = read_whole_file(path, &len);
    if (!blob) return -2;
    rc = lpk_decrypt(blob, len, password, out);
    free(blob);
    return rc;
}

int lpk_peek_file(const char *path, lpk_info_t *info)
{
    uint8_t *blob;
    size_t len = 0;
    int rc;
    if (!path || !info) return -1;
    blob = read_whole_file(path, &len);
    if (!blob) return -2;
    rc = lpk_peek(blob, len, info);
    free(blob);
    return rc;
}
