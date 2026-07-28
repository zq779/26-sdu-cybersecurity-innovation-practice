#include "sm3.h"

#if defined(__x86_64__) || defined(_M_X64)

#include "sm3_internal.h"
#include <immintrin.h>

static inline __m512i v512_rotl32(__m512i x, unsigned n)
{
    return _mm512_or_si512(_mm512_slli_epi32(x, n),
                           _mm512_srli_epi32(x, 32u - n));
}

static inline __m512i v512_p0(__m512i x)
{
    return _mm512_ternarylogic_epi32(x, v512_rotl32(x, 9),
                                     v512_rotl32(x, 17), 0x96);
}

static inline __m512i v512_p1(__m512i x)
{
    return _mm512_ternarylogic_epi32(x, v512_rotl32(x, 15),
                                     v512_rotl32(x, 23), 0x96);
}

static inline __m512i v512_xor3(__m512i x, __m512i y, __m512i z)
{
    return _mm512_ternarylogic_epi32(x, y, z, 0x96);
}

static inline __m512i v512_majority(__m512i x, __m512i y, __m512i z)
{
    return _mm512_ternarylogic_epi32(x, y, z, 0xe8);
}

static inline __m512i v512_choose(__m512i x, __m512i y, __m512i z)
{
    return _mm512_ternarylogic_epi32(x, y, z, 0xca);
}

static void sm3_compress16(__m512i state[8],
                           const uint8_t *const blocks[16],
                           __mmask16 active)
{
    __m512i w[68];
    uint32_t lane_word[16];

    for (unsigned j = 0; j < 16u; ++j) {
        for (unsigned lane = 0; lane < 16u; ++lane) {
            lane_word[lane] = (active & ((__mmask16)1u << lane))
                ? sm3_load_be32(blocks[lane] + 4u * j)
                : 0u;
        }
        w[j] = _mm512_loadu_si512((const void *)lane_word);
    }

    for (unsigned j = 16u; j < 68u; ++j) {
        const __m512i x = v512_xor3(w[j - 16u], w[j - 9u],
                                   v512_rotl32(w[j - 3u], 15));
        w[j] = v512_xor3(v512_p1(x), v512_rotl32(w[j - 13u], 7),
                         w[j - 6u]);
    }

    __m512i a = state[0];
    __m512i b = state[1];
    __m512i c = state[2];
    __m512i d = state[3];
    __m512i e = state[4];
    __m512i f = state[5];
    __m512i g = state[6];
    __m512i h = state[7];

    for (unsigned j = 0; j < 64u; ++j) {
        const __m512i a12 = v512_rotl32(a, 12);
        __m512i ss1 = _mm512_add_epi32(a12, e);
        ss1 = _mm512_add_epi32(ss1, _mm512_set1_epi32((int)sm3_t_rot(j)));
        ss1 = v512_rotl32(ss1, 7);
        const __m512i ss2 = _mm512_xor_si512(ss1, a12);
        const __m512i ff = (j < 16u) ? v512_xor3(a, b, c)
                                      : v512_majority(a, b, c);
        const __m512i gg = (j < 16u) ? v512_xor3(e, f, g)
                                      : v512_choose(e, f, g);
        const __m512i wp = _mm512_xor_si512(w[j], w[j + 4u]);
        __m512i tt1 = _mm512_add_epi32(ff, d);
        tt1 = _mm512_add_epi32(tt1, ss2);
        tt1 = _mm512_add_epi32(tt1, wp);
        __m512i tt2 = _mm512_add_epi32(gg, h);
        tt2 = _mm512_add_epi32(tt2, ss1);
        tt2 = _mm512_add_epi32(tt2, w[j]);

        d = c;
        c = v512_rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = v512_rotl32(f, 19);
        f = e;
        e = v512_p0(tt2);
    }

    const __m512i candidate[8] = {
        _mm512_xor_si512(state[0], a),
        _mm512_xor_si512(state[1], b),
        _mm512_xor_si512(state[2], c),
        _mm512_xor_si512(state[3], d),
        _mm512_xor_si512(state[4], e),
        _mm512_xor_si512(state[5], f),
        _mm512_xor_si512(state[6], g),
        _mm512_xor_si512(state[7], h)
    };
    for (unsigned i = 0; i < 8u; ++i) {
        state[i] = _mm512_mask_mov_epi32(state[i], active, candidate[i]);
    }
}

void sm3_avx512_hash16(const uint8_t *const msg[16], const size_t len[16],
                       uint8_t out[16][SM3_DIGEST_SIZE])
{
    __m512i state[8] = {
        _mm512_set1_epi32((int)SM3_IV0),
        _mm512_set1_epi32((int)SM3_IV1),
        _mm512_set1_epi32((int)SM3_IV2),
        _mm512_set1_epi32((int)SM3_IV3),
        _mm512_set1_epi32((int)SM3_IV4),
        _mm512_set1_epi32((int)SM3_IV5),
        _mm512_set1_epi32((int)SM3_IV6),
        _mm512_set1_epi32((int)SM3_IV7)
    };

    size_t max_full = 0u;
    for (unsigned lane = 0; lane < 16u; ++lane) {
        const size_t n = len[lane] / 64u;
        if (n > max_full) {
            max_full = n;
        }
    }

    static const uint8_t zero_block[64] = {0};
    for (size_t block_index = 0; block_index < max_full; ++block_index) {
        const uint8_t *blocks[16];
        __mmask16 active = 0u;
        for (unsigned lane = 0; lane < 16u; ++lane) {
            if (block_index < len[lane] / 64u) {
                blocks[lane] = msg[lane] + block_index * 64u;
                active |= (__mmask16)1u << lane;
            } else {
                blocks[lane] = zero_block;
            }
        }
        sm3_compress16(state, blocks, active);
    }

    uint8_t tails[16][128];
    size_t tail_blocks[16];
    const uint8_t *blocks[16];
    for (unsigned lane = 0; lane < 16u; ++lane) {
        tail_blocks[lane] = sm3_build_tail(msg[lane], len[lane], tails[lane]);
        blocks[lane] = tails[lane];
    }
    sm3_compress16(state, blocks, (__mmask16)0xffffu);

    __mmask16 second_active = 0u;
    for (unsigned lane = 0; lane < 16u; ++lane) {
        if (tail_blocks[lane] == 2u) {
            blocks[lane] = tails[lane] + 64u;
            second_active |= (__mmask16)1u << lane;
        } else {
            blocks[lane] = zero_block;
        }
    }
    if (second_active != 0u) {
        sm3_compress16(state, blocks, second_active);
    }

    uint32_t lanes[16];
    for (unsigned word = 0; word < 8u; ++word) {
        _mm512_storeu_si512((void *)lanes, state[word]);
        for (unsigned lane = 0; lane < 16u; ++lane) {
            sm3_store_be32(out[lane] + 4u * word, lanes[lane]);
        }
    }
}

#endif
