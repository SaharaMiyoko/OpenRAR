/*
 * OpenRAR - Clean-Room RAR 5.0 Compression & Decompression Engine
 * Implements RAR 5.0 v50 LZSS sliding window, 4-entry distance cache,
 * length-limited Canonical Huffman coding, RLE table serialization,
 * and post-processing filters (DELTA, E8, E8E9, ARM).
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_codec.h"
#include <algorithm>
#include <cstring>
#include <queue>
#include <tuple>

namespace openrar {

// ============================================================================
// Bitstream Writer & Reader Helpers
// ============================================================================

class BitStreamWriter {
public:
    void write_bits(uint32_t val, int nbits) {
        for (int i = nbits - 1; i >= 0; --i) {
            cur_byte_ = static_cast<uint8_t>((cur_byte_ << 1) | ((val >> i) & 1U));
            bit_count_++;
            if (bit_count_ == 8) {
                buf_.push_back(cur_byte_);
                cur_byte_ = 0;
                bit_count_ = 0;
            }
        }
    }

    // Finish bitstream and return (bytes, bit_size_minus_1)
    std::pair<std::vector<uint8_t>, uint8_t> finish() {
        std::vector<uint8_t> out = buf_;
        uint8_t bit_size_m1 = 7;
        if (bit_count_ > 0) {
            out.push_back(static_cast<uint8_t>(cur_byte_ << (8 - bit_count_)));
            bit_size_m1 = static_cast<uint8_t>(bit_count_ - 1);
        } else if (out.empty()) {
            out.push_back(0);
            bit_size_m1 = 0;
        }
        return {out, bit_size_m1};
    }

private:
    std::vector<uint8_t> buf_;
    uint8_t cur_byte_ = 0;
    int bit_count_ = 0;
};

// ============================================================================
// Canonical Huffman Tree Builder & Encoder
// ============================================================================

static void build_code_lengths(const uint32_t* freq, int alphabet_size, int max_bits, uint8_t* lengths) {
    std::memset(lengths, 0, alphabet_size);
    std::vector<int> active;
    for (int i = 0; i < alphabet_size; ++i) {
        if (freq[i] > 0) active.push_back(i);
    }
    if (active.empty()) {
        return;
    }
    if (active.size() == 1) {
        int s = active[0];
        int dummy = (s == 0) ? 1 : 0;
        lengths[s] = 1;
        lengths[dummy] = 1;
        return;
    }

    // Standard Huffman tree construction via min-heap
    struct Node {
        uint64_t weight;
        int parent;
        int left;
        int right;
    };
    int n_leaves = static_cast<int>(active.size());
    std::vector<Node> nodes(n_leaves * 2);
    using QItem = std::pair<uint64_t, int>;
    std::priority_queue<QItem, std::vector<QItem>, std::greater<QItem>> pq;

    for (int i = 0; i < n_leaves; ++i) {
        nodes[i] = {freq[active[i]], -1, -1, -1};
        pq.push({nodes[i].weight, i});
    }
    int next_node = n_leaves;
    while (pq.size() > 1) {
        auto [w1, n1] = pq.top(); pq.pop();
        auto [w2, n2] = pq.top(); pq.pop();
        int p = next_node++;
        nodes[p] = {w1 + w2, -1, n1, n2};
        nodes[n1].parent = p;
        nodes[n2].parent = p;
        pq.push({nodes[p].weight, p});
    }

    bool overflow = false;
    std::vector<int> sym_len(n_leaves);
    for (int i = 0; i < n_leaves; ++i) {
        int d = 0;
        int cur = i;
        while (nodes[cur].parent != -1) {
            d++;
            cur = nodes[cur].parent;
        }
        if (d > max_bits) {
            d = max_bits;
            overflow = true;
        }
        sym_len[i] = d;
    }

    if (overflow) {
        // Sort active indices by (sym_len ascending, freq descending)
        std::vector<int> order(n_leaves);
        for (int i = 0; i < n_leaves; ++i) order[i] = i;
        std::sort(order.begin(), order.end(), [&](int a, int b) {
            if (sym_len[a] != sym_len[b]) return sym_len[a] < sym_len[b];
            return freq[active[a]] > freq[active[b]];
        });

        const uint32_t target = (1U << max_bits);
        uint32_t kraft = 0;
        for (int i = 0; i < n_leaves; ++i) {
            kraft += (1U << (max_bits - sym_len[i]));
        }

        // Reduce kraft sum by lengthening deepest < max_bits symbols
        while (kraft > target) {
            for (int idx = n_leaves - 1; idx >= 0; --idx) {
                int i = order[idx];
                if (sym_len[i] < max_bits) {
                    uint32_t delta = 1U << (max_bits - sym_len[i] - 1);
                    sym_len[i]++;
                    kraft -= delta;
                    break;
                }
            }
        }

        // Increase kraft sum to exact target by shortening codes
        while (kraft < target) {
            bool changed = false;
            for (int idx = 0; idx < n_leaves; ++idx) {
                int i = order[idx];
                if (sym_len[i] > 1) {
                    uint32_t gain = 1U << (max_bits - sym_len[i]);
                    if (kraft + gain <= target) {
                        sym_len[i]--;
                        kraft += gain;
                        changed = true;
                        if (kraft == target) break;
                    }
                }
            }
            if (!changed) break;
        }
    }

    for (int i = 0; i < n_leaves; ++i) {
        lengths[active[i]] = static_cast<uint8_t>(sym_len[i]);
    }
}

static void build_canonical_codes(const uint8_t* lengths, int alphabet_size, uint16_t* codes) {
    int lc[16] = {0};
    for (int i = 0; i < alphabet_size; ++i) {
        if (lengths[i] > 0 && lengths[i] <= 15) {
            lc[lengths[i]]++;
        }
    }
    uint16_t first_code[16] = {0};
    uint16_t code = 0;
    for (int b = 1; b <= 15; ++b) {
        code = static_cast<uint16_t>((code + lc[b - 1]) << 1);
        first_code[b] = code;
    }
    std::memset(codes, 0, sizeof(uint16_t) * alphabet_size);
    for (int i = 0; i < alphabet_size; ++i) {
        uint8_t l = lengths[i];
        if (l > 0 && l <= 15) {
            codes[i] = first_code[l]++;
        }
    }
}

// ============================================================================
// RAR 5.0 Slot Mapping Helpers
// ============================================================================

static inline int floor_log2(uint32_t v) {
    int r = 0;
    while (v >>= 1) r++;
    return r;
}

static void len_to_slot(int encoded_len, int& slot, int& lbits, int& extra) {
    int v = encoded_len - 2;
    if (v < 8) {
        slot = v;
        lbits = 0;
        extra = 0;
    } else {
        int msb = floor_log2(static_cast<uint32_t>(v));
        lbits = msb - 2;
        slot = (lbits + 1) * 4 + ((v >> lbits) & 3);
        extra = v & ((1 << lbits) - 1);
    }
}

static void dist_to_slot(uint32_t dist, int& dist_slot, int& dbits, uint32_t& extra) {
    uint32_t d = dist - 1;
    if (d < 4) {
        dist_slot = static_cast<int>(d);
        dbits = 0;
        extra = 0;
    } else {
        int msb = floor_log2(d);
        dbits = msb - 1;
        dist_slot = (dbits + 1) * 2 + static_cast<int>((d >> dbits) & 1U);
        extra = d & ((1U << dbits) - 1U);
    }
}

static inline int dist_length_bonus(uint32_t dist) {
    int bonus = 0;
    if (dist > 0x100) {
        bonus++;
        if (dist > 0x2000) {
            bonus++;
            if (dist > 0x40000) {
                bonus++;
            }
        }
    }
    return bonus;
}

// ============================================================================
// Rar5Compressor Implementation
// ============================================================================

Rar5Compressor::Rar5Compressor() {
    reset(128 * 1024);
}

void Rar5Compressor::reset(size_t dict_size) {
    if (dict_size < 128 * 1024) dict_size = 128 * 1024;
    // Ensure power of 2
    size_t p2 = 128 * 1024;
    while (p2 < dict_size && p2 < (64ULL * 1024 * 1024)) p2 <<= 1;
    window_size_ = p2;
    window_mask_ = window_size_ - 1;
    window_.assign(window_size_, 0);
    write_ptr_ = 0;
    std::memset(dist_cache_, 0, sizeof(dist_cache_));
    last_len_ = 0;
    initialized_ = true;
}

struct LzToken {
    uint16_t lit_or_cmd;  // 0..255 literal, 257 repeat last, 258..261 repeat dist, 262..305 new match
    uint8_t  len_slot;    // for 258..261 (rd table) or 262..305 (num - 262)
    uint8_t  lbits;
    uint16_t lextra;
    uint8_t  dist_slot;   // for 262..305 (dd table)
    uint8_t  dbits;
    uint32_t dextra;
};

std::vector<uint8_t> Rar5Compressor::compress(const uint8_t* data, size_t len, int method,
                                              size_t dict_size, bool solid) {
    if (!initialized_ || !solid || window_size_ != dict_size) {
        reset(dict_size);
    } else {
        // Even in solid mode, verify dist_cache_ stays valid
    }

    // Configure LZSS search depth by compression method (1..5)
    int max_chain = 8;
    int nice_len = 32;
    switch (method) {
        case 1: max_chain = 4;   nice_len = 16;  break;
        case 2: max_chain = 12;  nice_len = 32;  break;
        case 3: max_chain = 32;  nice_len = 64;  break;
        case 4: max_chain = 96;  nice_len = 128; break;
        default: max_chain = 256; nice_len = 256; break;
    }

    // Process input in chunks of at most min(window_size / 2, 256KB) so each block fits
    // within libarchive's half-window unpack threshold and gets tailored Huffman tables.
    size_t max_chunk = std::min<size_t>(window_size_ >> 1, 256 * 1024);
    if (max_chunk == 0) max_chunk = 64 * 1024;

    // Hash table for 3-byte prefixes inside the sliding window
    constexpr size_t HASH_BITS = 15;
    constexpr size_t HASH_SIZE = 1 << HASH_BITS;
    std::vector<int64_t> head(HASH_SIZE, -1);
    std::vector<int64_t> prev(window_size_, -1);

    auto hash3 = [&](uint8_t b0, uint8_t b1, uint8_t b2) -> size_t {
        uint32_t h = (static_cast<uint32_t>(b0) << 16) ^
                     (static_cast<uint32_t>(b1) << 8) ^
                     static_cast<uint32_t>(b2);
        return ((h * 0x1E35A7BDu) >> (32 - HASH_BITS)) & (HASH_SIZE - 1);
    };

    std::vector<uint8_t> final_stream;
    size_t offset = 0;

    while (offset < len || (len == 0 && offset == 0)) {
        size_t chunk_len = std::min(max_chunk, len - offset);
        bool is_last_block = (offset + chunk_len >= len);

        std::vector<LzToken> tokens;
        tokens.reserve(chunk_len);

        uint32_t ld_freq[HUFF_NC] = {0};
        uint32_t dd_freq[HUFF_DC] = {0};
        uint32_t ldd_freq[HUFF_LDC] = {0};
        uint32_t rd_freq[HUFF_RC] = {0};

        size_t pos = offset;
        size_t chunk_end = offset + chunk_len;

        while (pos < chunk_end) {
            size_t rem = chunk_end - pos;
            uint64_t cur_abs = write_ptr_;

            int best_len = 1;
            uint32_t best_dist = 0;
            int best_rep_idx = -1; // -1 = not repeat, 0..3 = dist_cache_[idx], 4 = 257 (exact repeat)

            // 1. Check repeat distances in dist_cache_[0..3]
            if (rem >= 2) {
                for (int r = 0; r < 4; ++r) {
                    int d = dist_cache_[r];
                    if (d <= 0 || static_cast<uint64_t>(d) > cur_abs || static_cast<size_t>(d) > window_size_) {
                        continue;
                    }
                    int max_match = static_cast<int>(std::min<size_t>(rem, 4097));
                    int mlen = 0;
                    while (mlen < max_match &&
                           window_[(cur_abs - d + mlen) & window_mask_] == data[pos + mlen]) {
                        // Note: if mlen >= d, the match overlaps into the bytes we are currently matching!
                        mlen++;
                        if (mlen == d) break; // prevent reading unwritten window bytes before copy loop
                    }
                    // Also check overlapping self-repeat in data[]
                    if (mlen == d) {
                        while (mlen < max_match && data[pos + mlen - d] == data[pos + mlen]) {
                            mlen++;
                        }
                    }
                    if (r == 0 && last_len_ >= 2 && last_len_ <= max_match && mlen >= last_len_) {
                        // Check if exact repeat 257 is good
                        if (last_len_ > best_len) {
                            best_len = last_len_;
                            best_dist = static_cast<uint32_t>(d);
                            best_rep_idx = 4;
                        }
                    }
                    if (mlen >= 2 && mlen > best_len) {
                        best_len = mlen;
                        best_dist = static_cast<uint32_t>(d);
                        best_rep_idx = r;
                    }
                }
            }

            // 2. Search hash chain for new matches if rem >= 3
            if (rem >= 3 && best_len < nice_len) {
                size_t h = hash3(data[pos], data[pos + 1], data[pos + 2]);
                int64_t cand = head[h];
                int chain = max_chain;
                size_t max_dist = std::min<uint64_t>(cur_abs, window_size_ - 1);

                while (cand >= 0 && chain-- > 0) {
                    uint64_t dist64 = cur_abs - static_cast<uint64_t>(cand);
                    if (dist64 == 0 || dist64 > max_dist) break;
                    uint32_t d = static_cast<uint32_t>(dist64);
                    int bonus = dist_length_bonus(d);
                    int min_req = 2 + bonus;
                    int max_match = static_cast<int>(std::min<size_t>(rem, 4097 + bonus));

                    if (window_[(cand + best_len) & window_mask_] == data[pos + std::min<int>(best_len, max_match - 1)]) {
                        int mlen = 0;
                        while (mlen < max_match) {
                            uint8_t wb = (static_cast<uint32_t>(mlen) < d)
                                ? window_[(cand + mlen) & window_mask_]
                                : data[pos + mlen - d];
                            if (wb != data[pos + mlen]) break;
                            mlen++;
                        }
                        if (mlen >= min_req && mlen > best_len) {
                            best_len = mlen;
                            best_dist = d;
                            best_rep_idx = -1;
                            if (best_len >= nice_len) break;
                        }
                    }
                    cand = prev[cand & window_mask_];
                }
            }

            // Insert current position into hash table and window, and emit token
            if (best_len >= 2) {
                LzToken tok{};
                if (best_rep_idx == 4) {
                    // Code 257: repeat last_len_ with dist_cache_[0]
                    tok.lit_or_cmd = 257;
                    ld_freq[257]++;
                } else if (best_rep_idx >= 0 && best_rep_idx <= 3) {
                    // Code 258..261: repeat dist_cache_[idx] with length in rd
                    tok.lit_or_cmd = static_cast<uint16_t>(258 + best_rep_idx);
                    int slot = 0, lbits = 0, lextra = 0;
                    len_to_slot(best_len, slot, lbits, lextra);
                    tok.len_slot = static_cast<uint8_t>(slot);
                    tok.lbits = static_cast<uint8_t>(lbits);
                    tok.lextra = static_cast<uint16_t>(lextra);
                    ld_freq[tok.lit_or_cmd]++;
                    rd_freq[slot]++;

                    // Update dist_cache_ (touch best_rep_idx)
                    int d = dist_cache_[best_rep_idx];
                    for (int k = best_rep_idx; k > 0; --k) dist_cache_[k] = dist_cache_[k - 1];
                    dist_cache_[0] = d;
                    last_len_ = best_len;
                } else {
                    // Code 262..305: new match
                    int bonus = dist_length_bonus(best_dist);
                    int enc_len = best_len - bonus;
                    int lslot = 0, lbits = 0, lextra = 0;
                    len_to_slot(enc_len, lslot, lbits, lextra);

                    int dslot = 0, dbits = 0;
                    uint32_t dextra = 0;
                    dist_to_slot(best_dist, dslot, dbits, dextra);

                    tok.lit_or_cmd = static_cast<uint16_t>(262 + lslot);
                    tok.len_slot = static_cast<uint8_t>(lslot);
                    tok.lbits = static_cast<uint8_t>(lbits);
                    tok.lextra = static_cast<uint16_t>(lextra);
                    tok.dist_slot = static_cast<uint8_t>(dslot);
                    tok.dbits = static_cast<uint8_t>(dbits);
                    tok.dextra = dextra;

                    ld_freq[tok.lit_or_cmd]++;
                    dd_freq[dslot]++;
                    if (dbits >= 4) {
                        ldd_freq[dextra & 0x0F]++;
                    }

                    // Push best_dist into dist_cache_
                    dist_cache_[3] = dist_cache_[2];
                    dist_cache_[2] = dist_cache_[1];
                    dist_cache_[1] = dist_cache_[0];
                    dist_cache_[0] = static_cast<int>(best_dist);
                    last_len_ = best_len;
                }
                tokens.push_back(tok);

                // Advance window and hash chains for all matched bytes
                for (int k = 0; k < best_len; ++k) {
                    if (pos + k + 2 < len) {
                        size_t h = hash3(data[pos + k], data[pos + k + 1], data[pos + k + 2]);
                        prev[write_ptr_ & window_mask_] = head[h];
                        head[h] = static_cast<int64_t>(write_ptr_);
                    }
                    window_[write_ptr_ & window_mask_] = data[pos + k];
                    write_ptr_++;
                }
                pos += best_len;
            } else {
                // Literal byte
                uint8_t b = data[pos];
                LzToken tok{};
                tok.lit_or_cmd = b;
                ld_freq[b]++;
                tokens.push_back(tok);

                if (pos + 2 < len) {
                    size_t h = hash3(data[pos], data[pos + 1], data[pos + 2]);
                    prev[write_ptr_ & window_mask_] = head[h];
                    head[h] = static_cast<int64_t>(write_ptr_);
                }
                window_[write_ptr_ & window_mask_] = b;
                write_ptr_++;
                pos++;
            }
        }

        // Build the 4 Huffman code-length tables
        uint8_t ld_len[HUFF_NC] = {0};
        uint8_t dd_len[HUFF_DC] = {0};
        uint8_t ldd_len[HUFF_LDC] = {0};
        uint8_t rd_len[HUFF_RC] = {0};

        // Ensure at least 1 symbol in ld_len even for empty chunk
        if (tokens.empty()) {
            ld_freq[0] = 1;
        }

        build_code_lengths(ld_freq, HUFF_NC, MAX_HUFF_BITS, ld_len);
        build_code_lengths(dd_freq, HUFF_DC, MAX_HUFF_BITS, dd_len);
        build_code_lengths(ldd_freq, HUFF_LDC, MAX_HUFF_BITS, ldd_len);
        build_code_lengths(rd_freq, HUFF_RC, MAX_HUFF_BITS, rd_len);

        uint16_t ld_codes[HUFF_NC];
        uint16_t dd_codes[HUFF_DC];
        uint16_t ldd_codes[HUFF_LDC];
        uint16_t rd_codes[HUFF_RC];

        build_canonical_codes(ld_len, HUFF_NC, ld_codes);
        build_canonical_codes(dd_len, HUFF_DC, dd_codes);
        build_canonical_codes(ldd_len, HUFF_LDC, ldd_codes);
        build_canonical_codes(rd_len, HUFF_RC, rd_codes);

        // Concatenate all 430 code lengths and RLE-encode them for bd[20]
        uint8_t all_table[HUFF_TABLE_SIZE];
        std::memcpy(all_table, ld_len, HUFF_NC);
        std::memcpy(all_table + HUFF_NC, dd_len, HUFF_DC);
        std::memcpy(all_table + HUFF_NC + HUFF_DC, ldd_len, HUFF_LDC);
        std::memcpy(all_table + HUFF_NC + HUFF_DC + HUFF_LDC, rd_len, HUFF_RC);

        struct BdRleSym {
            uint8_t sym;
            uint8_t extra_bits;
            uint8_t extra_val;
        };
        std::vector<BdRleSym> rle_syms;
        uint32_t bd_freq[HUFF_BC] = {0};

        for (int i = 0; i < HUFF_TABLE_SIZE;) {
            uint8_t v = all_table[i];
            int run = 1;
            while (i + run < HUFF_TABLE_SIZE && all_table[i + run] == v) {
                run++;
            }
            i += run;
            if (v == 0) {
                while (run >= 11) {
                    int take = std::min(run, 138);
                    rle_syms.push_back({19, 7, static_cast<uint8_t>(take - 11)});
                    bd_freq[19]++;
                    run -= take;
                }
                if (run >= 3) {
                    rle_syms.push_back({18, 3, static_cast<uint8_t>(run - 3)});
                    bd_freq[18]++;
                    run = 0;
                }
                while (run-- > 0) {
                    rle_syms.push_back({0, 0, 0});
                    bd_freq[0]++;
                }
            } else {
                // Emit first occurrence of v
                rle_syms.push_back({v, 0, 0});
                bd_freq[v]++;
                run--;
                while (run >= 11) {
                    int take = std::min(run, 138);
                    rle_syms.push_back({17, 7, static_cast<uint8_t>(take - 11)});
                    bd_freq[17]++;
                    run -= take;
                }
                if (run >= 3) {
                    rle_syms.push_back({16, 3, static_cast<uint8_t>(run - 3)});
                    bd_freq[16]++;
                    run = 0;
                }
                while (run-- > 0) {
                    rle_syms.push_back({v, 0, 0});
                    bd_freq[v]++;
                }
            }
        }

        uint8_t bd_len[HUFF_BC] = {0};
        uint16_t bd_codes[HUFF_BC] = {0};
        build_code_lengths(bd_freq, HUFF_BC, MAX_HUFF_BITS, bd_len);
        build_canonical_codes(bd_len, HUFF_BC, bd_codes);

        // Write block payload to BitStreamWriter
        BitStreamWriter bw;
        for (int i = 0; i < HUFF_BC; ++i) {
            if (bd_len[i] == 15) {
                bw.write_bits(15, 4);
                bw.write_bits(0, 4);
            } else {
                bw.write_bits(bd_len[i], 4);
            }
        }
        for (const auto& s : rle_syms) {
            bw.write_bits(bd_codes[s.sym], bd_len[s.sym]);
            if (s.extra_bits > 0) {
                bw.write_bits(s.extra_val, s.extra_bits);
            }
        }

        // Write LZSS tokens
        for (const auto& tok : tokens) {
            uint16_t c = tok.lit_or_cmd;
            bw.write_bits(ld_codes[c], ld_len[c]);
            if (c >= 258 && c < 262) {
                bw.write_bits(rd_codes[tok.len_slot], rd_len[tok.len_slot]);
                if (tok.lbits > 0) {
                    bw.write_bits(tok.lextra, tok.lbits);
                }
            } else if (c >= 262) {
                if (tok.lbits > 0) {
                    bw.write_bits(tok.lextra, tok.lbits);
                }
                bw.write_bits(dd_codes[tok.dist_slot], dd_len[tok.dist_slot]);
                if (tok.dbits > 0) {
                    if (tok.dbits >= 4) {
                        if (tok.dbits > 4) {
                            bw.write_bits(tok.dextra >> 4, tok.dbits - 4);
                        }
                        uint8_t low_d = static_cast<uint8_t>(tok.dextra & 0x0F);
                        bw.write_bits(ldd_codes[low_d], ldd_len[low_d]);
                    } else {
                        bw.write_bits(tok.dextra, tok.dbits);
                    }
                }
            }
        }

        auto [payload, bit_size_m1] = bw.finish();
        uint32_t bsize = static_cast<uint32_t>(payload.size());
        uint8_t byte_count_code = 0;
        if (bsize <= 0xFF) byte_count_code = 0;
        else if (bsize <= 0xFFFF) byte_count_code = 1;
        else byte_count_code = 2;

        uint8_t block_flags = static_cast<uint8_t>(
            0x80 | // table present
            (is_last_block ? 0x40 : 0x00) |
            (byte_count_code << 3) |
            (bit_size_m1 & 7)
        );
        uint8_t block_cksum = static_cast<uint8_t>(
            0x5A ^ block_flags ^ (bsize & 0xFF) ^ ((bsize >> 8) & 0xFF) ^ ((bsize >> 16) & 0xFF)
        );

        final_stream.push_back(block_flags);
        final_stream.push_back(block_cksum);
        final_stream.push_back(static_cast<uint8_t>(bsize & 0xFF));
        if (byte_count_code >= 1) final_stream.push_back(static_cast<uint8_t>((bsize >> 8) & 0xFF));
        if (byte_count_code >= 2) final_stream.push_back(static_cast<uint8_t>((bsize >> 16) & 0xFF));
        final_stream.insert(final_stream.end(), payload.begin(), payload.end());

        offset += chunk_len;
        if (len == 0) break;
    }

    return final_stream;
}

// ============================================================================
// Rar5Decompressor Implementation
// ============================================================================

Rar5Decompressor::Rar5Decompressor() {
    reset(128 * 1024);
}

void Rar5Decompressor::reset(size_t dict_size) {
    if (dict_size < 128 * 1024) dict_size = 128 * 1024;
    size_t p2 = 128 * 1024;
    while (p2 < dict_size && p2 < (64ULL * 1024 * 1024)) p2 <<= 1;
    window_size_ = p2;
    window_mask_ = window_size_ - 1;
    window_.assign(window_size_, 0);
    write_ptr_ = 0;
    solid_offset_ = 0;
    std::memset(dist_cache_, 0, sizeof(dist_cache_));
    last_len_ = 0;
    std::memset(&bd_, 0, sizeof(bd_));
    std::memset(&ld_, 0, sizeof(ld_));
    std::memset(&dd_, 0, sizeof(dd_));
    std::memset(&ldd_, 0, sizeof(ldd_));
    std::memset(&rd_, 0, sizeof(rd_));
    initialized_ = true;
}

static bool create_decode_table(const uint8_t* bit_length, uint32_t size,
                                uint32_t quick_bits,
                                int32_t* decode_len, uint32_t* decode_pos,
                                uint8_t* quick_len, uint16_t* quick_num,
                                uint16_t* decode_num) {
    int lc[16] = {0};
    std::memset(decode_num, 0, sizeof(uint16_t) * HUFF_NC);
    for (uint32_t i = 0; i < size; ++i) {
        lc[bit_length[i] & 15]++;
    }
    lc[0] = 0;
    decode_pos[0] = 0;
    decode_len[0] = 0;
    int32_t upper_limit = 0;
    for (int i = 1; i < 16; ++i) {
        upper_limit += lc[i];
        decode_len[i] = upper_limit << (16 - i);
        decode_pos[i] = decode_pos[i - 1] + lc[i - 1];
        upper_limit <<= 1;
    }
    if (upper_limit > 65536) {
        return false;
    }
    uint32_t pos_clone[16];
    std::memcpy(pos_clone, decode_pos, sizeof(pos_clone));
    for (uint32_t i = 0; i < size; ++i) {
        uint8_t clen = bit_length[i] & 15;
        if (clen > 0) {
            uint32_t last_pos = pos_clone[clen];
            if (last_pos < size) {
                decode_num[last_pos] = static_cast<uint16_t>(i);
            }
            pos_clone[clen]++;
        }
    }
    uint32_t quick_data_size = 1U << quick_bits;
    uint32_t cur_len = 1;
    for (uint32_t code = 0; code < quick_data_size; ++code) {
        int32_t bit_field = static_cast<int32_t>(code << (16 - quick_bits));
        while (cur_len < 16 && bit_field >= decode_len[cur_len]) {
            cur_len++;
        }
        quick_len[code] = static_cast<uint8_t>(cur_len);
        int32_t dist = bit_field - decode_len[cur_len - 1];
        dist >>= (16 - cur_len);
        uint32_t pos = decode_pos[cur_len & 15] + static_cast<uint32_t>(dist);
        if (cur_len < 16 && pos < size) {
            quick_num[code] = decode_num[pos];
        } else {
            quick_num[code] = 0;
        }
    }
    return true;
}

bool Rar5Decompressor::decompress(const uint8_t* comp_data, size_t comp_len,
                                  uint64_t unpacked_size, int method,
                                  size_t dict_size, bool solid,
                                  std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(static_cast<size_t>(unpacked_size));

    if (method == 0) {
        if (comp_len < unpacked_size) return false;
        out.assign(comp_data, comp_data + static_cast<size_t>(unpacked_size));
        return true;
    }

    if (!initialized_ || !solid) {
        reset(dict_size);
    } else {
        if (dict_size > window_size_) {
            size_t p2 = window_size_;
            while (p2 < dict_size && p2 < (64ULL * 1024 * 1024)) p2 <<= 1;
            window_.resize(p2, 0);
            window_size_ = p2;
            window_mask_ = window_size_ - 1;
        }
        solid_offset_ += write_ptr_;
        write_ptr_ = 0;
    }

    if (unpacked_size == 0) {
        return true;
    }

    // Pad input buffer with 8 zero bytes for safe 24/32-bit lookahead
    std::vector<uint8_t> padded(comp_data, comp_data + comp_len);
    padded.resize(comp_len + 16, 0);

    size_t stream_pos = 0;
    int64_t last_write_ptr = 0;
    std::vector<FilterInfo> filters;

    auto flush_unfiltered = [&](int64_t end_pos) {
        while (last_write_ptr < end_pos) {
            uint8_t b = window_[static_cast<size_t>((solid_offset_ + last_write_ptr) & window_mask_)];
            out.push_back(b);
            last_write_ptr++;
        }
    };

    auto apply_pending_filters = [&]() -> bool {
        while (!filters.empty()) {
            const FilterInfo& flt = filters.front();
            if (write_ptr_ > flt.block_start &&
                write_ptr_ >= flt.block_start + static_cast<int64_t>(flt.block_length)) {
                flush_unfiltered(flt.block_start);
                std::vector<uint8_t> fbuf(flt.block_length, 0);
                if (flt.type == FILTER5_DELTA) {
                    int ch = std::max(1, flt.channels);
                    size_t src_pos = 0;
                    for (int c = 0; c < ch; ++c) {
                        uint8_t prev_b = 0;
                        for (size_t dpos = c; dpos < flt.block_length; dpos += ch) {
                            uint8_t b = window_[static_cast<size_t>((solid_offset_ + flt.block_start + src_pos) & window_mask_)];
                            prev_b = static_cast<uint8_t>(prev_b - b);
                            fbuf[dpos] = prev_b;
                            src_pos++;
                        }
                    }
                } else if (flt.type == FILTER5_E8 || flt.type == FILTER5_E8E9) {
                    for (size_t i = 0; i < flt.block_length; ++i) {
                        fbuf[i] = window_[static_cast<size_t>((solid_offset_ + flt.block_start + i) & window_mask_)];
                    }
                    const uint32_t file_size = 0x1000000U;
                    bool ext = (flt.type == FILTER5_E8E9);
                    if (flt.block_length >= 5) {
                        for (size_t i = 0; i < flt.block_length - 4;) {
                            uint8_t b = fbuf[i++];
                            if (b == 0xE8 || (ext && b == 0xE9)) {
                                uint32_t off = static_cast<uint32_t>((i + flt.block_start) % file_size);
                                uint32_t addr = read_u32_le(&fbuf[i]);
                                if (addr & 0x80000000U) {
                                    if (((addr + off) & 0x80000000U) == 0) {
                                        uint32_t v = addr + file_size;
                                        fbuf[i+0] = v & 0xFF; fbuf[i+1] = (v>>8)&0xFF;
                                        fbuf[i+2] = (v>>16)&0xFF; fbuf[i+3] = (v>>24)&0xFF;
                                    }
                                } else {
                                    if ((addr - file_size) & 0x80000000U) {
                                        uint32_t v = addr - off;
                                        fbuf[i+0] = v & 0xFF; fbuf[i+1] = (v>>8)&0xFF;
                                        fbuf[i+2] = (v>>16)&0xFF; fbuf[i+3] = (v>>24)&0xFF;
                                    }
                                }
                                i += 4;
                            }
                        }
                    }
                } else if (flt.type == FILTER5_ARM) {
                    for (size_t i = 0; i < flt.block_length; ++i) {
                        fbuf[i] = window_[static_cast<size_t>((solid_offset_ + flt.block_start + i) & window_mask_)];
                    }
                    if (flt.block_length >= 4) {
                        for (size_t i = 0; i <= flt.block_length - 4; i += 4) {
                            if (fbuf[i + 3] == 0xEB) {
                                uint32_t off = read_u32_le(&fbuf[i]) & 0x00FFFFFFU;
                                off -= static_cast<uint32_t>((i + flt.block_start) / 4);
                                off = (off & 0x00FFFFFFU) | 0xEB000000U;
                                fbuf[i+0] = off & 0xFF; fbuf[i+1] = (off>>8)&0xFF;
                                fbuf[i+2] = (off>>16)&0xFF; fbuf[i+3] = (off>>24)&0xFF;
                            }
                        }
                    }
                } else {
                    return false;
                }
                out.insert(out.end(), fbuf.begin(), fbuf.end());
                last_write_ptr += static_cast<int64_t>(flt.block_length);
                filters.erase(filters.begin());
            } else {
                break;
            }
        }
        return true;
    };

    while (stream_pos < comp_len) {
        if (stream_pos + 3 > comp_len) return false;
        uint8_t block_flags = padded[stream_pos];
        uint8_t block_cksum = padded[stream_pos + 1];
        uint8_t byte_count = (block_flags >> 3) & 7;
        if (byte_count > 2) return false;
        size_t hdr_len = 2 + byte_count + 1;
        if (stream_pos + hdr_len > comp_len) return false;

        uint32_t block_size = 0;
        if (byte_count == 0) block_size = padded[stream_pos + 2];
        else if (byte_count == 1) block_size = padded[stream_pos + 2] | (uint32_t(padded[stream_pos + 3]) << 8);
        else block_size = padded[stream_pos + 2] | (uint32_t(padded[stream_pos + 3]) << 8) | (uint32_t(padded[stream_pos + 4]) << 16);

        uint8_t calc_cksum = static_cast<uint8_t>(
            0x5A ^ block_flags ^ (block_size & 0xFF) ^ ((block_size >> 8) & 0xFF) ^ ((block_size >> 16) & 0xFF)
        );
        if (calc_cksum != block_cksum) return false;

        stream_pos += hdr_len;
        if (stream_pos + block_size > comp_len) return false;

        const uint8_t* p = padded.data() + stream_pos;
        int in_addr = 0;
        int bit_addr = 0;
        int cur_block_size = static_cast<int>(block_size);
        uint8_t bit_size = 1 + (block_flags & 7);
        bool table_present = ((block_flags >> 7) & 1) != 0;
        bool is_last_block = ((block_flags >> 6) & 1) != 0;

        auto read_bits_16 = [&]() -> uint16_t {
            uint32_t b24 = (static_cast<uint32_t>(p[in_addr]) << 16) |
                           (static_cast<uint32_t>(p[in_addr + 1]) << 8) |
                           static_cast<uint32_t>(p[in_addr + 2]);
            return static_cast<uint16_t>((b24 >> (8 - bit_addr)) & 0xFFFFU);
        };
        auto read_bits_32 = [&]() -> uint32_t {
            uint32_t b32 = (static_cast<uint32_t>(p[in_addr]) << 24) |
                           (static_cast<uint32_t>(p[in_addr + 1]) << 16) |
                           (static_cast<uint32_t>(p[in_addr + 2]) << 8) |
                           static_cast<uint32_t>(p[in_addr + 3]);
            b32 <<= bit_addr;
            b32 |= static_cast<uint32_t>(p[in_addr + 4]) >> (8 - bit_addr);
            return b32;
        };
        auto skip_bits = [&](int n) {
            int nb = bit_addr + n;
            in_addr += nb >> 3;
            bit_addr = nb & 7;
        };
        auto read_consume_bits = [&](int n) -> int {
            uint16_t v = read_bits_16();
            int res = static_cast<int>(v >> (16 - n));
            skip_bits(n);
            return res;
        };
        auto decode_number = [&](DecodeTable& tbl, uint16_t& num) -> bool {
            if (in_addr >= cur_block_size) return false;
            uint16_t bf = read_bits_16() & 0xFFFEU;
            if (bf < tbl.decode_len[tbl.quick_bits]) {
                uint32_t code = bf >> (16 - tbl.quick_bits);
                skip_bits(tbl.quick_len[code]);
                num = tbl.quick_num[code];
                return true;
            }
            int bits = 15;
            for (int i = static_cast<int>(tbl.quick_bits) + 1; i < 15; ++i) {
                if (bf < tbl.decode_len[i]) {
                    bits = i;
                    break;
                }
            }
            skip_bits(bits);
            int dist = (bf - tbl.decode_len[bits - 1]) >> (16 - bits);
            uint32_t pos = tbl.decode_pos[bits] + static_cast<uint32_t>(dist);
            if (pos >= tbl.size) pos = 0;
            num = tbl.decode_num[pos];
            return true;
        };

        if (table_present) {
            uint8_t bit_length[HUFF_BC] = {0};
            uint8_t table[HUFF_TABLE_SIZE] = {0};
            uint8_t nibble_mask = 0xF0;
            uint8_t nibble_shift = 4;
            int i = 0;
            for (int w = 0; w < HUFF_BC;) {
                if (i >= cur_block_size) return false;
                int value = (p[i] & nibble_mask) >> nibble_shift;
                if (nibble_mask == 0x0F) ++i;
                nibble_mask ^= 0xFF;
                nibble_shift ^= 4;
                if (value == 15) {
                    if (i >= cur_block_size) return false;
                    value = (p[i] & nibble_mask) >> nibble_shift;
                    if (nibble_mask == 0x0F) ++i;
                    nibble_mask ^= 0xFF;
                    nibble_shift ^= 4;
                    if (value == 0) {
                        bit_length[w++] = 15;
                    } else {
                        for (int k = 0; k < value + 2 && w < HUFF_BC; ++k) {
                            bit_length[w++] = 0;
                        }
                    }
                } else {
                    bit_length[w++] = static_cast<uint8_t>(value);
                }
            }
            in_addr = i;
            bit_addr = nibble_shift ^ 4;

            bd_.size = HUFF_BC; bd_.quick_bits = 7;
            if (!create_decode_table(bit_length, HUFF_BC, 7, bd_.decode_len, bd_.decode_pos,
                                     bd_.quick_len, bd_.quick_num, bd_.decode_num)) {
                return false;
            }
            for (int idx = 0; idx < HUFF_TABLE_SIZE;) {
                uint16_t num = 0;
                if (!decode_number(bd_, num)) return false;
                if (num < 16) {
                    table[idx++] = static_cast<uint8_t>(num);
                } else if (num < 18) {
                    if (idx == 0) return false;
                    int n = (num == 16) ? (read_consume_bits(3) + 3) : (read_consume_bits(7) + 11);
                    while (n-- > 0 && idx < HUFF_TABLE_SIZE) {
                        table[idx] = table[idx - 1];
                        idx++;
                    }
                } else {
                    int n = (num == 18) ? (read_consume_bits(3) + 3) : (read_consume_bits(7) + 11);
                    while (n-- > 0 && idx < HUFF_TABLE_SIZE) {
                        table[idx++] = 0;
                    }
                }
            }

            ld_.size = HUFF_NC; ld_.quick_bits = 10;
            dd_.size = HUFF_DC; dd_.quick_bits = 7;
            ldd_.size = HUFF_LDC; ldd_.quick_bits = 7;
            rd_.size = HUFF_RC; rd_.quick_bits = 7;

            if (!create_decode_table(&table[0], HUFF_NC, 10, ld_.decode_len, ld_.decode_pos, ld_.quick_len, ld_.quick_num, ld_.decode_num)) return false;
            if (!create_decode_table(&table[HUFF_NC], HUFF_DC, 7, dd_.decode_len, dd_.decode_pos, dd_.quick_len, dd_.quick_num, dd_.decode_num)) return false;
            if (!create_decode_table(&table[HUFF_NC + HUFF_DC], HUFF_LDC, 7, ldd_.decode_len, ldd_.decode_pos, ldd_.quick_len, ldd_.quick_num, ldd_.decode_num)) return false;
            if (!create_decode_table(&table[HUFF_NC + HUFF_DC + HUFF_LDC], HUFF_RC, 7, rd_.decode_len, rd_.decode_pos, rd_.quick_len, rd_.quick_num, rd_.decode_num)) return false;
        }

        auto decode_code_len = [&](uint16_t code) -> int {
            int lbits = 0, length = 2;
            if (code < 8) {
                lbits = 0;
                length += code;
            } else {
                lbits = code / 4 - 1;
                length += (4 | (code & 3)) << lbits;
            }
            if (lbits > 0) {
                length += read_consume_bits(lbits);
            }
            return length;
        };

        auto copy_string = [&](int len, int dist) -> bool {
            uint64_t wptr = static_cast<uint64_t>(write_ptr_ + solid_offset_);
            for (int k = 0; k < len; ++k) {
                size_t w_idx = static_cast<size_t>((wptr + k) & window_mask_);
                size_t r_idx = static_cast<size_t>((wptr + k - dist) & window_mask_);
                window_[w_idx] = window_[r_idx];
            }
            write_ptr_ += len;
            return true;
        };

        // Decode tokens in this block
        while (true) {
            if (in_addr > cur_block_size - 1 ||
                (in_addr == cur_block_size - 1 && bit_addr >= bit_size)) {
                break;
            }

            uint16_t num = 0;
            if (!decode_number(ld_, num)) return false;

            if (num < 256) {
                size_t w_idx = static_cast<size_t>((solid_offset_ + write_ptr_) & window_mask_);
                window_[w_idx] = static_cast<uint8_t>(num);
                write_ptr_++;
            } else if (num >= 262) {
                int len = decode_code_len(num - 262);
                uint16_t dist_slot = 0;
                if (!decode_number(dd_, dist_slot)) return false;
                int dbits = 0;
                uint32_t dist = 1;
                if (dist_slot < 4) {
                    dbits = 0;
                    dist += dist_slot;
                } else {
                    dbits = dist_slot / 2 - 1;
                    dist += (2U | (dist_slot & 1U)) << dbits;
                }
                if (dbits > 0) {
                    if (dbits >= 4) {
                        if (dbits > 4) {
                            uint32_t add = read_bits_32();
                            skip_bits(dbits - 4);
                            add = (add >> (36 - dbits)) << 4;
                            dist += add;
                        }
                        uint16_t low_dist = 0;
                        if (!decode_number(ldd_, low_dist)) return false;
                        dist += low_dist;
                    } else {
                        dist += static_cast<uint32_t>(read_consume_bits(dbits));
                    }
                }
                if (dist > 0x100) {
                    len++;
                    if (dist > 0x2000) {
                        len++;
                        if (dist > 0x40000) len++;
                    }
                }
                dist_cache_[3] = dist_cache_[2];
                dist_cache_[2] = dist_cache_[1];
                dist_cache_[1] = dist_cache_[0];
                dist_cache_[0] = static_cast<int>(dist);
                last_len_ = len;
                copy_string(len, static_cast<int>(dist));
            } else if (num == 256) {
                // Parse filter
                auto read_flt_data = [&]() -> uint32_t {
                    int bytes = read_consume_bits(2) + 1;
                    uint32_t d = 0;
                    for (int b = 0; b < bytes; ++b) {
                        d += static_cast<uint32_t>(read_consume_bits(8)) << (b * 8);
                    }
                    return d;
                };
                uint32_t bstart = read_flt_data();
                uint32_t blen = read_flt_data();
                int ftype = read_consume_bits(3);
                FilterInfo flt{};
                flt.type = ftype;
                flt.block_start = write_ptr_ + static_cast<int64_t>(bstart);
                flt.block_length = blen;
                if (ftype == FILTER5_DELTA) {
                    flt.channels = read_consume_bits(5) + 1;
                }
                filters.push_back(flt);
            } else if (num == 257) {
                if (last_len_ != 0) {
                    copy_string(last_len_, dist_cache_[0]);
                }
            } else {
                // 258..261: repeat distance from dist_cache_
                int idx = num - 258;
                int dist = dist_cache_[idx];
                for (int k = idx; k > 0; --k) dist_cache_[k] = dist_cache_[k - 1];
                dist_cache_[0] = dist;

                uint16_t len_slot = 0;
                if (!decode_number(rd_, len_slot)) return false;
                int len = decode_code_len(len_slot);
                last_len_ = len;
                copy_string(len, dist);
            }

            if ((write_ptr_ - last_write_ptr) > static_cast<int64_t>(window_size_ >> 1)) {
                if (!apply_pending_filters()) return false;
                int64_t max_end = filters.empty() ? write_ptr_ : std::min(filters.front().block_start, write_ptr_);
                flush_unfiltered(max_end);
            }
        }

        if (!apply_pending_filters()) return false;
        int64_t max_end = filters.empty() ? write_ptr_ : std::min(filters.front().block_start, write_ptr_);
        flush_unfiltered(max_end);

        stream_pos += block_size;
        if (is_last_block) break;
    }

    if (!apply_pending_filters()) return false;
    flush_unfiltered(write_ptr_);

    if (out.size() > unpacked_size) {
        out.resize(static_cast<size_t>(unpacked_size));
    }
    return out.size() == unpacked_size;
}

} // namespace openrar
