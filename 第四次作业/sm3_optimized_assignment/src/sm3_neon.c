#include "sm3.h"

#if defined(__aarch64__)

#include "sm3_internal.h"
#include <arm_neon.h>

static inline uint32x4_t v128_rotl32(uint32x4_t x, int n)
{
    const int32x4_t left = vdupq_n_s32(n);
    const int32x4_t right = vdupq_n_s32(n - 32);
    return vorrq_u32(vshlq_u32(x, left), vshlq_u32(x, right));
}

static inline uint32x4_t v128_xor3(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return veorq_u32(veorq_u32(x, y), z);
}

static inline uint32x4_t v128_p0(uint32x4_t x)
{
    return v128_xor3(x, v128_rotl32(x, 9), v128_rotl32(x, 17));
}

static inline uint32x4_t v128_p1(uint32x4_t x)
{
    return v128_xor3(x, v128_rotl32(x, 15), v128_rotl32(x, 23));
}

static inline uint32x4_t v128_majority(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return vorrq_u32(vandq_u32(x, y),
           vorrq_u32(vandq_u32(x, z), vandq_u32(y, z)));
}

static inline uint32x4_t v128_choose(uint32x4_t x, uint32x4_t y, uint32x4_t z)
{
    return vorrq_u32(vandq_u32(x, y), vbicq_u32(z, x));
}

static uint32x4_t v128_active_mask(unsigned bits)
{
    uint32_t m[4];
    for (unsigned i = 0; i < 4u; ++i) {
        m[i] = (bits & (1u << i)) ? UINT32_MAX : 0u;
    }
    return vld1q_u32(m);
}

static void sm3_compress4(uint32x4_t state[8],
                          const uint8_t *const blocks[4],
                          unsigned active_bits)
{
    uint32x4_t w[68];
    uint32_t lane_word[4];

    for (unsigned j = 0; j < 16u; ++j) {
        for (unsigned lane = 0; lane < 4u; ++lane) {
            lane_word[lane] = (active_bits & (1u << lane))
                ? sm3_load_be32(blocks[lane] + 4u * j)
                : 0u;
        }
        w[j] = vld1q_u32(lane_word);
    }

    for (unsigned j = 16u; j < 68u; ++j) {
        const uint32x4_t x = v128_xor3(w[j - 16u], w[j - 9u],
                                      v128_rotl32(w[j - 3u], 15));
        w[j] = v128_xor3(v128_p1(x), v128_rotl32(w[j - 13u], 7),
                         w[j - 6u]);
    }

    uint32x4_t a = state[0];
    uint32x4_t b = state[1];
    uint32x4_t c = state[2];
    uint32x4_t d = state[3];
    uint32x4_t e = state[4];
    uint32x4_t f = state[5];
    uint32x4_t g = state[6];
    uint32x4_t h = state[7];

    for (unsigned j = 0; j < 64u; ++j) {
        const uint32x4_t a12 = v128_rotl32(a, 12);
        uint32x4_t ss1 = vaddq_u32(a12, e);
        ss1 = vaddq_u32(ss1, vdupq_n_u32(sm3_t_rot(j)));
        ss1 = v128_rotl32(ss1, 7);
        const uint32x4_t ss2 = veorq_u32(ss1, a12);
        const uint32x4_t ff = (j < 16u) ? v128_xor3(a, b, c)
                                         : v128_majority(a, b, c);
        const uint32x4_t gg = (j < 16u) ? v128_xor3(e, f, g)
                                         : v128_choose(e, f, g);
        const uint32x4_t wp = veorq_u32(w[j], w[j + 4u]);
        uint32x4_t tt1 = vaddq_u32(ff, d);
        tt1 = vaddq_u32(tt1, ss2);
        tt1 = vaddq_u32(tt1, wp);
        uint32x4_t tt2 = vaddq_u32(gg, h);
        tt2 = vaddq_u32(tt2, ss1);
        tt2 = vaddq_u32(tt2, w[j]);

        d = c;
        c = v128_rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = v128_rotl32(f, 19);
        f = e;
        e = v128_p0(tt2);
    }

    const uint32x4_t mask = v128_active_mask(active_bits);
    const uint32x4_t candidate[8] = {
        veorq_u32(state[0], a),
        veorq_u32(state[1], b),
        veorq_u32(state[2], c),
        veorq_u32(state[3], d),
        veorq_u32(state[4], e),
        veorq_u32(state[5], f),
        veorq_u32(state[6], g),
        veorq_u32(state[7], h)
    };
    for (unsigned i = 0; i < 8u; ++i) {
        state[i] = vbslq_u32(mask, candidate[i], state[i]);
    }
}

void sm3_neon_hash4(const uint8_t *const msg[4], const size_t len[4],
                    uint8_t out[4][SM3_DIGEST_SIZE])
{
    uint32x4_t state[8] = {
        vdupq_n_u32(SM3_IV0), vdupq_n_u32(SM3_IV1),
        vdupq_n_u32(SM3_IV2), vdupq_n_u32(SM3_IV3),
        vdupq_n_u32(SM3_IV4), vdupq_n_u32(SM3_IV5),
        vdupq_n_u32(SM3_IV6), vdupq_n_u32(SM3_IV7)
    };

    size_t max_full = 0u;
    for (unsigned lane = 0; lane < 4u; ++lane) {
        const size_t n = len[lane] / 64u;
        if (n > max_full) {
            max_full = n;
        }
    }

    static const uint8_t zero_block[64] = {0};
    for (size_t block_index = 0; block_index < max_full; ++block_index) {
        const uint8_t *blocks[4];
        unsigned active = 0u;
        for (unsigned lane = 0; lane < 4u; ++lane) {
            if (block_index < len[lane] / 64u) {
                blocks[lane] = msg[lane] + block_index * 64u;
                active |= 1u << lane;
            } else {
                blocks[lane] = zero_block;
            }
        }
        sm3_compress4(state, blocks, active);
    }

    uint8_t tails[4][128];
    size_t tail_blocks[4];
    const uint8_t *blocks[4];
    for (unsigned lane = 0; lane < 4u; ++lane) {
        tail_blocks[lane] = sm3_build_tail(msg[lane], len[lane], tails[lane]);
        blocks[lane] = tails[lane];
    }
    sm3_compress4(state, blocks, 0x0fu);

    unsigned second_active = 0u;
    for (unsigned lane = 0; lane < 4u; ++lane) {
        if (tail_blocks[lane] == 2u) {
            blocks[lane] = tails[lane] + 64u;
            second_active |= 1u << lane;
        } else {
            blocks[lane] = zero_block;
        }
    }
    if (second_active != 0u) {
        sm3_compress4(state, blocks, second_active);
    }

    uint32_t lanes[4];
    for (unsigned word = 0; word < 8u; ++word) {
        vst1q_u32(lanes, state[word]);
        for (unsigned lane = 0; lane < 4u; ++lane) {
            sm3_store_be32(out[lane] + 4u * word, lanes[lane]);
        }
    }
}

#endif
