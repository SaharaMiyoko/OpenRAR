/*
 * OpenRAR - Clean-Room Cryptographic & Checksum Primitives for RAR 5.0
 * Implements CRC32, BLAKE2sp, SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, and AES-256-CBC.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_crypto.h"
#include "rar_defs.h"
#include <cstring>
#include <random>
#include <algorithm>

namespace openrar {

// ============================================================================
// 1. CRC32 (IEEE 802.3 polynomial 0xEDB88320)
// ============================================================================

static uint32_t g_crc32_table[256];
static bool g_crc32_initialized = false;

static void init_crc32_table() {
    if (g_crc32_initialized) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        g_crc32_table[i] = c;
    }
    g_crc32_initialized = true;
}

uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) {
    if (!g_crc32_initialized) init_crc32_table();
    uint32_t c = crc ^ 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) {
        c = g_crc32_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFU;
}

uint32_t crc32_compute(const uint8_t* data, size_t len) {
    return crc32_update(0, data, len);
}

// ============================================================================
// 2. BLAKE2s & BLAKE2sp (RFC 7693 / BLAKE2 8-way parallel tree hash)
// ============================================================================

static constexpr uint32_t BLAKE2S_IV[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
};

static constexpr uint8_t BLAKE2S_SIGMA[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }
};

static inline uint32_t rotr32(uint32_t w, unsigned c) {
    return (w >> c) | (w << (32 - c));
}

static void blake2s_increment_counter(Blake2sState* S, uint32_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc) ? 1U : 0U;
}

static void blake2s_compress(Blake2sState* S, const uint8_t block[64]) {
    uint32_t m[16];
    uint32_t v[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = read_u32_le(block + i * 4);
    }
    for (int i = 0; i < 8; ++i) {
        v[i] = S->h[i];
        v[i + 8] = BLAKE2S_IV[i];
    }
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    v[14] ^= S->f[0];
    v[15] ^= S->f[1];

    auto G = [&](int r, int i, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a = a + b + m[BLAKE2S_SIGMA[r][2 * i + 0]];
        d = rotr32(d ^ a, 16);
        c = c + d;
        b = rotr32(b ^ c, 12);
        a = a + b + m[BLAKE2S_SIGMA[r][2 * i + 1]];
        d = rotr32(d ^ a, 8);
        c = c + d;
        b = rotr32(b ^ c, 7);
    };

    for (int r = 0; r < 10; ++r) {
        G(r, 0, v[0], v[4], v[ 8], v[12]);
        G(r, 1, v[1], v[5], v[ 9], v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[ 8], v[13]);
        G(r, 7, v[3], v[4], v[ 9], v[14]);
    }
    for (int i = 0; i < 8; ++i) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2s_init_param(Blake2sState* S, uint32_t node_offset, uint8_t node_depth, bool last_node) {
    std::memset(S, 0, sizeof(Blake2sState));
    for (int i = 0; i < 8; ++i) S->h[i] = BLAKE2S_IV[i];
    // Parameter block for BLAKE2sp (digest_length=32, key_length=0, fanout=8, depth=2, inner_length=32)
    S->h[0] ^= 0x02080020U;
    S->h[1] ^= 0x00000000U; // leaf_length = 0
    S->h[2] ^= node_offset;
    S->h[3] ^= (static_cast<uint32_t>(32) << 24) | (static_cast<uint32_t>(node_depth) << 16);
    S->last_node = last_node;
}

static void blake2s_update(Blake2sState* S, const uint8_t* in, size_t inlen) {
    if (inlen == 0) return;
    size_t left = S->buflen;
    size_t fill = 64 - left;
    if (inlen > fill) {
        S->buflen = 0;
        std::memcpy(S->buf + left, in, fill);
        blake2s_increment_counter(S, 64);
        blake2s_compress(S, S->buf);
        in += fill;
        inlen -= fill;
        while (inlen > 64) {
            blake2s_increment_counter(S, 64);
            blake2s_compress(S, in);
            in += 64;
            inlen -= 64;
        }
    }
    std::memcpy(S->buf + S->buflen, in, inlen);
    S->buflen += inlen;
}

static void blake2s_final(Blake2sState* S, uint8_t out[32]) {
    blake2s_increment_counter(S, static_cast<uint32_t>(S->buflen));
    S->f[0] = 0xFFFFFFFFU;
    if (S->last_node) S->f[1] = 0xFFFFFFFFU;
    std::memset(S->buf + S->buflen, 0, 64 - S->buflen);
    blake2s_compress(S, S->buf);
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>(S->h[i] & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((S->h[i] >> 8) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((S->h[i] >> 16) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>((S->h[i] >> 24) & 0xFF);
    }
}

void blake2sp_init(Blake2spState* S) {
    std::memset(S->buf, 0, sizeof(S->buf));
    S->buflen = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        blake2s_init_param(&S->leaves[i], i, 0, i == 7);
    }
    blake2s_init_param(&S->root, 0, 1, true);
}

void blake2sp_update(Blake2spState* S, const uint8_t* in, size_t inlen) {
    size_t left = S->buflen;
    size_t fill = 512 - left;
    if (inlen >= fill) {
        std::memcpy(S->buf + left, in, fill);
        for (size_t i = 0; i < 8; ++i) {
            blake2s_update(&S->leaves[i], S->buf + i * 64, 64);
        }
        in += fill;
        inlen -= fill;
        left = 0;
        while (inlen >= 512) {
            for (size_t i = 0; i < 8; ++i) {
                blake2s_update(&S->leaves[i], in + i * 64, 64);
            }
            in += 512;
            inlen -= 512;
        }
    }
    if (inlen > 0) {
        std::memcpy(S->buf + left, in, inlen);
    }
    S->buflen = left + inlen;
}

void blake2sp_final(Blake2spState* S, uint8_t out[32]) {
    for (size_t i = 0; i < 8; ++i) {
        if (S->buflen > i * 64) {
            size_t inlen = S->buflen - i * 64;
            if (inlen > 64) inlen = 64;
            blake2s_update(&S->leaves[i], S->buf + i * 64, inlen);
        }
        uint8_t leaf_hash[32];
        blake2s_final(&S->leaves[i], leaf_hash);
        blake2s_update(&S->root, leaf_hash, 32);
    }
    blake2s_final(&S->root, out);
}

void blake2sp_compute(const uint8_t* data, size_t len, uint8_t out[32]) {
    Blake2spState S;
    blake2sp_init(&S);
    blake2sp_update(&S, data, len);
    blake2sp_final(&S, out);
}

// ============================================================================
// 3. SHA-256 & HMAC-SHA256 (FIPS 180-4)
// ============================================================================

static constexpr uint32_t SHA256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_transform(Sha256State* s, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8)  |
               (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void sha256_init(Sha256State* s) {
    s->h[0] = 0x6a09e667U; s->h[1] = 0xbb67ae85U; s->h[2] = 0x3c6ef372U; s->h[3] = 0xa54ff53aU;
    s->h[4] = 0x510e527fU; s->h[5] = 0x9b05688cU; s->h[6] = 0x1f83d9abU; s->h[7] = 0x5be0cd19U;
    s->total_bits = 0;
    s->buflen = 0;
}

void sha256_update(Sha256State* s, const uint8_t* data, size_t len) {
    s->total_bits += static_cast<uint64_t>(len) * 8;
    while (len > 0) {
        size_t take = std::min(len, 64 - s->buflen);
        std::memcpy(s->buf + s->buflen, data, take);
        s->buflen += take;
        data += take;
        len -= take;
        if (s->buflen == 64) {
            sha256_transform(s, s->buf);
            s->buflen = 0;
        }
    }
}

void sha256_final(Sha256State* s, uint8_t out[32]) {
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56) {
        std::memset(s->buf + s->buflen, 0, 64 - s->buflen);
        sha256_transform(s, s->buf);
        s->buflen = 0;
    }
    std::memset(s->buf + s->buflen, 0, 56 - s->buflen);
    for (int i = 0; i < 8; ++i) {
        s->buf[63 - i] = static_cast<uint8_t>((s->total_bits >> (i * 8)) & 0xFF);
    }
    sha256_transform(s, s->buf);
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>((s->h[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((s->h[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((s->h[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>(s->h[i] & 0xFF);
    }
}

void sha256_compute(const uint8_t* data, size_t len, uint8_t out[32]) {
    Sha256State s;
    sha256_init(&s);
    sha256_update(&s, data, len);
    sha256_final(&s, out);
}

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
    uint8_t k_pad[64];
    std::memset(k_pad, 0, 64);
    if (key_len > 64) {
        sha256_compute(key, key_len, k_pad);
    } else {
        std::memcpy(k_pad, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }
    Sha256State inner, outer;
    uint8_t inner_hash[32];
    sha256_init(&inner);
    sha256_update(&inner, ipad, 64);
    sha256_update(&inner, msg, msg_len);
    sha256_final(&inner, inner_hash);

    sha256_init(&outer);
    sha256_update(&outer, opad, 64);
    sha256_update(&outer, inner_hash, 32);
    sha256_final(&outer, out);
}

// ============================================================================
// 4. RAR 5.0 PBKDF2-HMAC-SHA256 Key Derivation & Checksum Tweaking
// ============================================================================

Rar5KeyMaterial derive_rar5_keys(const std::string& password, const uint8_t salt[16], uint8_t lg2_count) {
    Rar5KeyMaterial res{};
    const uint8_t* pwd = reinterpret_cast<const uint8_t*>(password.data());
    size_t pwd_len = password.size();

    // Precompute HMAC inner and outer states after absorbing ipad and opad
    uint8_t k_pad[64];
    std::memset(k_pad, 0, 64);
    if (pwd_len > 64) {
        sha256_compute(pwd, pwd_len, k_pad);
    } else {
        std::memcpy(k_pad, pwd, pwd_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }
    Sha256State base_inner, base_outer;
    sha256_init(&base_inner);
    sha256_update(&base_inner, ipad, 64);
    sha256_init(&base_outer);
    sha256_update(&base_outer, opad, 64);

    auto fast_hmac = [&](const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
        Sha256State in_s = base_inner;
        Sha256State out_s = base_outer;
        uint8_t tmp[32];
        sha256_update(&in_s, msg, msg_len);
        sha256_final(&in_s, tmp);
        sha256_update(&out_s, tmp, 32);
        sha256_final(&out_s, out);
    };

    uint8_t salt_blk[20];
    std::memcpy(salt_blk, salt, 16);
    salt_blk[16] = 0; salt_blk[17] = 0; salt_blk[18] = 0; salt_blk[19] = 1;

    uint8_t u[32], t[32], psw_check_val[32];
    fast_hmac(salt_blk, 20, u);
    std::memcpy(t, u, 32);

    uint32_t iterations = (1U << lg2_count);
    uint32_t total_iters = iterations + 32;
    for (uint32_t i = 1; i < total_iters; ++i) {
        fast_hmac(u, 32, u);
        for (int j = 0; j < 32; ++j) {
            t[j] ^= u[j];
        }
        if (i == iterations - 1) {
            std::memcpy(res.aes_key, t, 32);
        } else if (i == iterations + 16 - 1) {
            std::memcpy(res.hash_key, t, 32);
        } else if (i == iterations + 32 - 1) {
            std::memcpy(psw_check_val, t, 32);
        }
    }

    std::memset(res.psw_check, 0, 8);
    for (int i = 0; i < 32; ++i) {
        res.psw_check[i & 7] ^= psw_check_val[i];
    }
    uint8_t csum_full[32];
    sha256_compute(res.psw_check, 8, csum_full);
    std::memcpy(res.check_csum, csum_full, 4);
    std::memcpy(res.check_value, res.psw_check, 8);
    std::memcpy(res.check_value + 8, res.check_csum, 4);
    return res;
}

bool verify_rar5_password(const Rar5KeyMaterial& keys, const uint8_t check_value[12]) {
    return std::memcmp(keys.check_value, check_value, 12) == 0;
}

uint32_t tweak_rar5_crc32(uint32_t crc, const uint8_t hash_key[32]) {
    uint8_t crc_le[4];
    crc_le[0] = static_cast<uint8_t>(crc & 0xFF);
    crc_le[1] = static_cast<uint8_t>((crc >> 8) & 0xFF);
    crc_le[2] = static_cast<uint8_t>((crc >> 16) & 0xFF);
    crc_le[3] = static_cast<uint8_t>((crc >> 24) & 0xFF);
    uint8_t mac[32];
    hmac_sha256(hash_key, 32, crc_le, 4, mac);
    uint32_t tweaked = 0;
    for (int i = 0; i < 32; ++i) {
        tweaked ^= static_cast<uint32_t>(mac[i]) << ((i & 3) * 8);
    }
    return tweaked;
}

void tweak_rar5_blake2sp(const uint8_t in_hash[32], const uint8_t hash_key[32], uint8_t out_hash[32]) {
    hmac_sha256(hash_key, 32, in_hash, 32, out_hash);
}

// ============================================================================
// 5. AES-256-CBC (FIPS 197)
// ============================================================================

static constexpr uint8_t AES_SBOX[256] = {
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

static constexpr uint8_t AES_INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static constexpr uint8_t AES_RCON[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d
};

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void aes256_expand_key(const uint8_t key[32], uint8_t round_keys[240]) {
    std::memcpy(round_keys, key, 32);
    uint8_t temp[4];
    int bytes_generated = 32;
    int rcon_iter = 1;
    while (bytes_generated < 240) {
        for (int i = 0; i < 4; ++i) temp[i] = round_keys[bytes_generated - 4 + i];
        if (bytes_generated % 32 == 0) {
            uint8_t k = temp[0];
            temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rcon_iter++];
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[k];
        } else if (bytes_generated % 32 == 16) {
            for (int i = 0; i < 4; ++i) temp[i] = AES_SBOX[temp[i]];
        }
        for (int i = 0; i < 4; ++i) {
            round_keys[bytes_generated] = round_keys[bytes_generated - 32] ^ temp[i];
            bytes_generated++;
        }
    }
}

static void aes256_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[240]) {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[i];
    for (int round = 1; round <= 14; ++round) {
        for (int i = 0; i < 16; ++i) s[i] = AES_SBOX[s[i]];
        // ShiftRows
        uint8_t t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
        // MixColumns
        if (round < 14) {
            for (int c = 0; c < 4; ++c) {
                uint8_t s0 = s[c*4+0], s1 = s[c*4+1], s2 = s[c*4+2], s3 = s[c*4+3];
                s[c*4+0] = gf_mul(2, s0) ^ gf_mul(3, s1) ^ s2 ^ s3;
                s[c*4+1] = s0 ^ gf_mul(2, s1) ^ gf_mul(3, s2) ^ s3;
                s[c*4+2] = s0 ^ s1 ^ gf_mul(2, s2) ^ gf_mul(3, s3);
                s[c*4+3] = gf_mul(3, s0) ^ s1 ^ s2 ^ gf_mul(2, s3);
            }
        }
        for (int i = 0; i < 16; ++i) s[i] ^= rk[round * 16 + i];
    }
    std::memcpy(out, s, 16);
}

static void aes256_decrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[240]) {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = in[i] ^ rk[14 * 16 + i];
    for (int round = 13; round >= 0; --round) {
        // InvShiftRows
        uint8_t t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
        // InvSubBytes
        for (int i = 0; i < 16; ++i) s[i] = AES_INV_SBOX[s[i]];
        // AddRoundKey
        for (int i = 0; i < 16; ++i) s[i] ^= rk[round * 16 + i];
        // InvMixColumns
        if (round > 0) {
            for (int c = 0; c < 4; ++c) {
                uint8_t s0 = s[c*4+0], s1 = s[c*4+1], s2 = s[c*4+2], s3 = s[c*4+3];
                s[c*4+0] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
                s[c*4+1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
                s[c*4+2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
                s[c*4+3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
            }
        }
    }
    std::memcpy(out, s, 16);
}

std::vector<uint8_t> aes256_cbc_encrypt(const uint8_t* data, size_t len, const uint8_t key[32], const uint8_t iv[16]) {
    size_t padded_len = (len == 0) ? 16 : ((len + 15) & ~size_t(15));
    std::vector<uint8_t> out(padded_len, 0);
    uint8_t rk[240];
    aes256_expand_key(key, rk);
    uint8_t prev[16];
    std::memcpy(prev, iv, 16);
    for (size_t off = 0; off < padded_len; off += 16) {
        uint8_t blk[16] = {0};
        if (off < len) {
            size_t copy_len = std::min<size_t>(16, len - off);
            std::memcpy(blk, data + off, copy_len);
        }
        for (int i = 0; i < 16; ++i) blk[i] ^= prev[i];
        aes256_encrypt_block(blk, out.data() + off, rk);
        std::memcpy(prev, out.data() + off, 16);
    }
    return out;
}

std::vector<uint8_t> aes256_cbc_decrypt(const uint8_t* data, size_t len, const uint8_t key[32], const uint8_t iv[16]) {
    size_t aligned_len = len & ~size_t(15);
    std::vector<uint8_t> out(aligned_len, 0);
    uint8_t rk[240];
    aes256_expand_key(key, rk);
    uint8_t prev[16];
    std::memcpy(prev, iv, 16);
    for (size_t off = 0; off < aligned_len; off += 16) {
        uint8_t dec[16];
        aes256_decrypt_block(data + off, dec, rk);
        for (int i = 0; i < 16; ++i) out[off + i] = dec[i] ^ prev[i];
        std::memcpy(prev, data + off, 16);
    }
    return out;
}

void random_bytes(uint8_t* out, size_t len) {
    std::random_device rd;
    for (size_t i = 0; i < len; ++i) {
        out[i] = static_cast<uint8_t>(rd() & 0xFF);
    }
}

} // namespace openrar
