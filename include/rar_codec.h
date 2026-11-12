/*
 * OpenRAR - Clean-Room RAR 5.0 Compression & Decompression Engine
 * Implements RAR 5.0 v50 LZSS sliding window, 4-entry distance cache,
 * length-limited Canonical Huffman coding, RLE table serialization,
 * and post-processing filters (DELTA, E8, E8E9, ARM).
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_CODEC_H
#define OPENRAR_CODEC_H

#include "rar_defs.h"
#include <cstdint>
#include <cstddef>
#include <vector>

namespace openrar {

// RAR 5.0 Compression Engine (LZSS + Canonical Huffman)
class Rar5Compressor {
public:
    Rar5Compressor();

    // Reset state (called at start of archive or non-solid file)
    void reset(size_t dict_size = 128 * 1024);

    // Compress a file's raw bytes into a RAR 5.0 compressed bitstream.
    // method: 1 (fastest) .. 5 (best)
    // dict_size: power-of-2 dictionary size (128KB .. 64MB)
    // solid: if true, preserves sliding dictionary & dist_cache from previous file
    std::vector<uint8_t> compress(const uint8_t* data, size_t len, int method = 3,
                                  size_t dict_size = 128 * 1024, bool solid = false);

private:
    std::vector<uint8_t> window_;
    size_t window_size_ = 0;
    size_t window_mask_ = 0;
    uint64_t write_ptr_ = 0;
    int dist_cache_[4] = {0, 0, 0, 0};
    int last_len_ = 0;
    bool initialized_ = false;
};

// RAR 5.0 Decompression Engine
class Rar5Decompressor {
public:
    Rar5Decompressor();

    void reset(size_t dict_size = 128 * 1024);

    // Decompress a RAR 5.0 compressed bitstream into `out`.
    // Returns true on success, false on corrupted bitstream.
    bool decompress(const uint8_t* comp_data, size_t comp_len,
                    uint64_t unpacked_size, int method,
                    size_t dict_size, bool solid,
                    std::vector<uint8_t>& out);

private:
    struct DecodeTable {
        uint32_t size = 0;
        int32_t  decode_len[16] = {0};
        uint32_t decode_pos[16] = {0};
        uint32_t quick_bits = 0;
        uint8_t  quick_len[1 << 10] = {0};
        uint16_t quick_num[1 << 10] = {0};
        uint16_t decode_num[HUFF_NC] = {0};
    };

    struct FilterInfo {
        int type = 0;
        int channels = 0;
        int64_t block_start = 0;
        size_t block_length = 0;
    };

    std::vector<uint8_t> window_;
    size_t window_size_ = 0;
    size_t window_mask_ = 0;
    int64_t write_ptr_ = 0;
    int64_t solid_offset_ = 0;
    int dist_cache_[4] = {0, 0, 0, 0};
    int last_len_ = 0;
    bool initialized_ = false;

    DecodeTable bd_;
    DecodeTable ld_;
    DecodeTable dd_;
    DecodeTable ldd_;
    DecodeTable rd_;
};

} // namespace openrar

#endif // OPENRAR_CODEC_H
