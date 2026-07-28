#include "sm3.h"

#if defined(__x86_64__) || defined(_M_X64)

#include "sm3_internal.h"
#include <immintrin.h>

static inline __m256i v256_rotl32(__m256i x, int n)
{
    return _mm256_or_si256(_mm256_slli_epi32(x, n),
                           _mm256_srli_epi32(x, 32 - n));
}

static inline __m256i v256_p0(__m256i x)
{
    return _mm256_xor_si256(x,
           _mm256_xor_si256(v256_rotl32(x, 9), v256_rotl32(x, 17)));
}

static inline __m256i v256_p1(__m256i x)
{
    return _mm256_xor_si256(x,
           _mm256_xor_si256(v256_rotl32(x, 15), v256_rotl32(x, 23)));
}

static inline __m256i v256_xor3(__m256i x, __m256i y, __m256i z)
{
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

static inline __m256i v256_majority(__m256i x, __m256i y, __m256i z)
{
    return _mm256_or_si256(_mm256_and_si256(x, y),
           _mm256_or_si256(_mm256_and_si256(x, z),
                           _mm256_and_si256(y, z)));
}

static inline __m256i v256_choose(__m256i x, __m256i y, __m256i z)
{
    return _mm256_or_si256(_mm256_and_si256(x, y),
                           _mm256_andnot_si256(x, z));
}

static __m256i v256_active_mask(unsigned bits)
{
    uint32_t m[8];
    for (unsigned i = 0; i < 8u; ++i) {
        m[i] = (bits & (1u << i)) ? UINT32_MAX : 0u;
    }
    return _mm256_loadu_si256((const __m256i *)(const void *)m);
}

static void sm3_compress8(__m256i state[8],
                          const uint8_t *const blocks[8],
                          unsigned active_bits)
{
    __m256i w[68];
    uint32_t lane_word[8];

    for (unsigned j = 0; j < 16u; ++j) {
        for (unsigned lane = 0; lane < 8u; ++lane) {
            lane_word[lane] = (active_bits & (1u << lane))
                ? sm3_load_be32(blocks[lane] + 4u * j)
                : 0u;
        }
        w[j] = _mm256_loadu_si256((const __m256i *)(const void *)lane_word);
    }

    for (unsigned j = 16u; j < 68u; ++j) {
        const __m256i x = v256_xor3(w[j - 16u], w[j - 9u],
                                   v256_rotl32(w[j - 3u], 15));
        w[j] = v256_xor3(v256_p1(x), v256_rotl32(w[j - 13u], 7),
                         w[j - 6u]);
    }

    __m256i a = state[0];
    __m256i b = state[1];
    __m256i c = state[2];
    __m256i d = state[3];
    __m256i e = state[4];
    __m256i f = state[5];
    __m256i g = state[6];
    __m256i h = state[7];

    for (unsigned j = 0; j < 64u; ++j) {
        const __m256i a12 = v256_rotl32(a, 12);
        __m256i ss1 = _mm256_add_epi32(a12, e);
        ss1 = _mm256_add_epi32(ss1, _mm256_set1_epi32((int)sm3_t_rot(j)));
        ss1 = v256_rotl32(ss1, 7);
        const __m256i ss2 = _mm256_xor_si256(ss1, a12);
        const __m256i ff = (j < 16u) ? v256_xor3(a, b, c)
                                      : v256_majority(a, b, c);
        const __m256i gg = (j < 16u) ? v256_xor3(e, f, g)
                                      : v256_choose(e, f, g);
        const __m256i wp = _mm256_xor_si256(w[j], w[j + 4u]);
        __m256i tt1 = _mm256_add_epi32(ff, d);
        tt1 = _mm256_add_epi32(tt1, ss2);
        tt1 = _mm256_add_epi32(tt1, wp);
        __m256i tt2 = _mm256_add_epi32(gg, h);
        tt2 = _mm256_add_epi32(tt2, ss1);
        tt2 = _mm256_add_epi32(tt2, w[j]);

        d = c;
        c = v256_rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = v256_rotl32(f, 19);
        f = e;
        e = v256_p0(tt2);
    }

    const __m256i mask = v256_active_mask(active_bits);
    const __m256i candidate[8] = {
        _mm256_xor_si256(state[0], a),
        _mm256_xor_si256(state[1], b),
        _mm256_xor_si256(state[2], c),
        _mm256_xor_si256(state[3], d),
        _mm256_xor_si256(state[4], e),
        _mm256_xor_si256(state[5], f),
        _mm256_xor_si256(state[6], g),
        _mm256_xor_si256(state[7], h)
    };
    for (unsigned i = 0; i < 8u; ++i) {
        state[i] = _mm256_blendv_epi8(state[i], candidate[i], mask);
    }
}

void sm3_avx2_hash8(const uint8_t *const msg[8], const size_t len[8],
                    uint8_t out[8][SM3_DIGEST_SIZE])
{
    __m256i state[8] = {
        _mm256_set1_epi32((int)SM3_IV0),
        _mm256_set1_epi32((int)SM3_IV1),
        _mm256_set1_epi32((int)SM3_IV2),
        _mm256_set1_epi32((int)SM3_IV3),
        _mm256_set1_epi32((int)SM3_IV4),
        _mm256_set1_epi32((int)SM3_IV5),
        _mm256_set1_epi32((int)SM3_IV6),
        _mm256_set1_epi32((int)SM3_IV7)
    };

    size_t max_full = 0u;
    for (unsigned lane = 0; lane < 8u; ++lane) {
        const size_t n = len[lane] / 64u;
        if (n > max_full) {
            max_full = n;
        }
    }

    static const uint8_t zero_block[64] = {0};
    for (size_t block_index = 0; block_index < max_full; ++block_index) {
        const uint8_t *blocks[8];
        unsigned active = 0u;
        for (unsigned lane = 0; lane < 8u; ++lane) {
            if (block_index < len[lane] / 64u) {
                blocks[lane] = msg[lane] + block_index * 64u;
                active |= 1u << lane;
            } else {
                blocks[lane] = zero_block;
            }
        }
        sm3_compress8(state, blocks, active);
    }

    uint8_t tails[8][128];
    size_t tail_blocks[8];
    const uint8_t *blocks[8];
    for (unsigned lane = 0; lane < 8u; ++lane) {
        tail_blocks[lane] = sm3_build_tail(msg[lane], len[lane], tails[lane]);
        blocks[lane] = tails[lane];
    }
    sm3_compress8(state, blocks, 0xffu);

    unsigned second_active = 0u;
    for (unsigned lane = 0; lane < 8u; ++lane) {
        if (tail_blocks[lane] == 2u) {
            blocks[lane] = tails[lane] + 64u;
            second_active |= 1u << lane;
        } else {
            blocks[lane] = zero_block;
        }
    }
    if (second_active != 0u) {
        sm3_compress8(state, blocks, second_active);
    }

    uint32_t lanes[8];
    for (unsigned word = 0; word < 8u; ++word) {
        _mm256_storeu_si256((__m256i *)(void *)lanes, state[word]);
        for (unsigned lane = 0; lane < 8u; ++lane) {
            sm3_store_be32(out[lane] + 4u * word, lanes[lane]);
        }
    }
    _mm256_zeroupper();
}

#endif
