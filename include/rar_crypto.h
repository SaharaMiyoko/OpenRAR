/*
 * OpenRAR - Clean-Room Cryptographic & Checksum Primitives for RAR 5.0
 * Implements CRC32, BLAKE2sp, SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, and AES-256-CBC.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_CRYPTO_H
#define OPENRAR_CRYPTO_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace openrar {

// CRC32 (IEEE 802.3)
uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len);
uint32_t crc32_compute(const uint8_t* data, size_t len);

// BLAKE2s & BLAKE2sp (8-way parallel tree hash, 32-byte digest)
struct Blake2sState {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[64];
    size_t   buflen;
    bool     last_node;
};

struct Blake2spState {
    Blake2sState leaves[8];
    Blake2sState root;
    uint8_t      buf[512];
    size_t       buflen;
};

void blake2sp_init(Blake2spState* S);
void blake2sp_update(Blake2spState* S, const uint8_t* data, size_t len);
void blake2sp_final(Blake2spState* S, uint8_t out[32]);
void blake2sp_compute(const uint8_t* data, size_t len, uint8_t out[32]);

// SHA-256 & HMAC-SHA256
struct Sha256State {
    uint32_t h[8];
    uint64_t total_bits;
    uint8_t  buf[64];
    size_t   buflen;
};

void sha256_init(Sha256State* s);
void sha256_update(Sha256State* s, const uint8_t* data, size_t len);
void sha256_final(Sha256State* s, uint8_t out[32]);
void sha256_compute(const uint8_t* data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]);

// RAR 5.0 PBKDF2-HMAC-SHA256 Key Derivation & Checksum Tweaking
struct Rar5KeyMaterial {
    uint8_t aes_key[32];
    uint8_t hash_key[32];
    uint8_t psw_check[8];
    uint8_t check_csum[4];
    uint8_t check_value[12]; // psw_check[8] || check_csum[4]
};

Rar5KeyMaterial derive_rar5_keys(const std::string& password, const uint8_t salt[16], uint8_t lg2_count = 15);
bool verify_rar5_password(const Rar5KeyMaterial& keys, const uint8_t check_value[12]);
uint32_t tweak_rar5_crc32(uint32_t crc, const uint8_t hash_key[32]);
void tweak_rar5_blake2sp(const uint8_t in_hash[32], const uint8_t hash_key[32], uint8_t out_hash[32]);

// AES-256-CBC (zero/random padded to 16-byte block alignment as per RAR 5.0 spec)
std::vector<uint8_t> aes256_cbc_encrypt(const uint8_t* data, size_t len, const uint8_t key[32], const uint8_t iv[16]);
std::vector<uint8_t> aes256_cbc_decrypt(const uint8_t* data, size_t len, const uint8_t key[32], const uint8_t iv[16]);

// Cryptographically random bytes for Salt and IV generation
void random_bytes(uint8_t* out, size_t len);

} // namespace openrar

#endif // OPENRAR_CRYPTO_H
