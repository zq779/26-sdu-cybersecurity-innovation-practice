#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "secp256k1.h"

/*
 * secp256k1 基点 G 的阶：
 *
 * n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
 *     BAAEDCE6AF48A03BBFD25E8CD0364141
 */
#define SECP256K1_ORDER_HEX \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

/* 以十六进制打印 32 字节数据。 */
static void print_hex(
    const char *label,
    const unsigned char *data,
    size_t length
) {
    printf("%s", label);

    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }

    printf("\n");
}

/*
 * 生成一个位于 [1, n-1] 的合法 secp256k1 标量。
 *
 * secp256k1_ec_seckey_verify 虽然名字中包含 seckey，
 * 但本质上是在检查一个 32 字节整数是否属于合法标量范围。
 */
static int random_valid_scalar(
    const secp256k1_context *ctx,
    unsigned char scalar32[32]
) {
    for (int attempt = 0; attempt < 1000; attempt++) {
        if (RAND_bytes(scalar32, 32) != 1) {
            return 0;
        }

        if (secp256k1_ec_seckey_verify(ctx, scalar32)) {
            return 1;
        }
    }

    return 0;
}

/* 将 BIGNUM 转换成固定长度的 32 字节大端整数。 */
static int bn_to_bytes32(
    const BIGNUM *number,
    unsigned char output[32]
) {
    return BN_bn2binpad(number, output, 32) == 32;
}

/*
 * 在不知道受害者私钥的情况下构造：
 *
 *   chosen_hash = e'
 *   signature   = (r', s')
 *
 * 使其能够通过受害者公钥的 ECDSA 验证。
 *
 * 这个函数只接收 victim_pubkey，不接收 victim_seckey，
 * 因而构造过程中无法使用受害者私钥。
 */
static int forge_chosen_hash_signature(
    const secp256k1_context *ctx,
    const secp256k1_pubkey *victim_pubkey,
    unsigned char chosen_hash[32],
    secp256k1_ecdsa_signature *forged_signature
) {
    int success = 0;

    BN_CTX *bn_ctx = NULL;

    BIGNUM *order = NULL;
    BIGNUM *half_order = NULL;

    BIGNUM *u_bn = NULL;
    BIGNUM *v_bn = NULL;
    BIGNUM *v_inverse = NULL;

    BIGNUM *r_bn = NULL;
    BIGNUM *s_bn = NULL;
    BIGNUM *e_bn = NULL;

    unsigned char u32[32];
    unsigned char v32[32];

    unsigned char compact_signature[64];
    unsigned char serialized_point[65];

    bn_ctx = BN_CTX_new();

    if (bn_ctx == NULL) {
        fprintf(stderr, "BN_CTX_new failed\n");
        goto cleanup;
    }

    if (BN_hex2bn(&order, SECP256K1_ORDER_HEX) == 0) {
        fprintf(stderr, "Failed to initialize curve order\n");
        goto cleanup;
    }

    half_order = BN_dup(order);
    u_bn = BN_new();
    v_bn = BN_new();
    v_inverse = BN_new();
    r_bn = BN_new();
    s_bn = BN_new();
    e_bn = BN_new();

    if (
        half_order == NULL ||
        u_bn == NULL ||
        v_bn == NULL ||
        v_inverse == NULL ||
        r_bn == NULL ||
        s_bn == NULL ||
        e_bn == NULL
    ) {
        fprintf(stderr, "BIGNUM allocation failed\n");
        goto cleanup;
    }

    /*
     * half_order = floor(n / 2)
     *
     * libsecp256k1 默认只接受 lower-S 签名，
     * 因而最终必须保证 s <= n/2。
     */
    if (BN_rshift1(half_order, half_order) != 1) {
        fprintf(stderr, "Failed to compute half order\n");
        goto cleanup;
    }

    for (int attempt = 0; attempt < 100; attempt++) {
        secp256k1_pubkey point_uG;
        secp256k1_pubkey point_vP;
        secp256k1_pubkey point_R;

        const secp256k1_pubkey *points_to_combine[2];

        size_t serialized_length = sizeof(serialized_point);

        /*
         * 攻击者随机选择：
         *
         *   u, v ∈ Z_n^*
         */
        if (!random_valid_scalar(ctx, u32)) {
            fprintf(stderr, "Failed to generate u\n");
            goto cleanup;
        }

        if (!random_valid_scalar(ctx, v32)) {
            fprintf(stderr, "Failed to generate v\n");
            goto cleanup;
        }

        /*
         * 计算：
         *
         *   uG
         */
        if (!secp256k1_ec_pubkey_create(ctx, &point_uG, u32)) {
            continue;
        }

        /*
         * 计算：
         *
         *   vP
         *
         * 先复制受害者公钥 P，再对其进行标量乘法。
         */
        point_vP = *victim_pubkey;

        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &point_vP, v32)) {
            continue;
        }

        /*
         * 计算：
         *
         *   R' = uG + vP
         */
        points_to_combine[0] = &point_uG;
        points_to_combine[1] = &point_vP;

        if (
            !secp256k1_ec_pubkey_combine(
                ctx,
                &point_R,
                points_to_combine,
                2
            )
        ) {
            continue;
        }

        /*
         * 使用未压缩形式序列化 R'：
         *
         *   04 || x' || y'
         *
         * 其中：
         *
         *   serialized_point[1...32] 为 x'
         */
        if (
            !secp256k1_ec_pubkey_serialize(
                ctx,
                serialized_point,
                &serialized_length,
                &point_R,
                SECP256K1_EC_UNCOMPRESSED
            )
        ) {
            continue;
        }

        if (serialized_length != 65) {
            continue;
        }

        /*
         * r' = x' mod n
         */
        if (
            BN_bin2bn(
                serialized_point + 1,
                32,
                r_bn
            ) == NULL
        ) {
            goto cleanup;
        }

        if (BN_mod(r_bn, r_bn, order, bn_ctx) != 1) {
            goto cleanup;
        }

        if (BN_is_zero(r_bn)) {
            continue;
        }

        /*
         * 将 u、v 转换成 BIGNUM。
         */
        if (BN_bin2bn(u32, 32, u_bn) == NULL) {
            goto cleanup;
        }

        if (BN_bin2bn(v32, 32, v_bn) == NULL) {
            goto cleanup;
        }

        /*
         * 计算：
         *
         *   v^{-1} mod n
         */
        if (
            BN_mod_inverse(
                v_inverse,
                v_bn,
                order,
                bn_ctx
            ) == NULL
        ) {
            continue;
        }

        /*
         * 构造：
         *
         *   s' = r' · v^{-1} mod n
         */
        if (
            BN_mod_mul(
                s_bn,
                r_bn,
                v_inverse,
                order,
                bn_ctx
            ) != 1
        ) {
            goto cleanup;
        }

        if (BN_is_zero(s_bn)) {
            continue;
        }

        /*
         * 构造：
         *
         *   e' = u · s' mod n
         *
         * 因为 s' = r'v^{-1}，所以也有：
         *
         *   e' = ur'v^{-1} mod n
         */
        if (
            BN_mod_mul(
                e_bn,
                u_bn,
                s_bn,
                order,
                bn_ctx
            ) != 1
        ) {
            goto cleanup;
        }

        /*
         * 官方库只接受 lower-S。
         *
         * 若 s' > n/2，则令：
         *
         *   s' <- n - s'
         *
         * 这对应把验证点 R' 替换成 -R'。
         * R' 与 -R' 的横坐标相同，因此签名依然通过验证。
         *
         * 注意：e' 保持原值不变。
         */
        if (BN_cmp(s_bn, half_order) > 0) {
            if (BN_sub(s_bn, order, s_bn) != 1) {
                goto cleanup;
            }
        }

        /*
         * compact_signature = r' || s'
         */
        if (!bn_to_bytes32(r_bn, compact_signature)) {
            goto cleanup;
        }

        if (!bn_to_bytes32(s_bn, compact_signature + 32)) {
            goto cleanup;
        }

        if (!bn_to_bytes32(e_bn, chosen_hash)) {
            goto cleanup;
        }

        /*
         * 将手工构造的 r'、s' 解析为官方签名对象。
         */
        if (
            !secp256k1_ecdsa_signature_parse_compact(
                ctx,
                forged_signature,
                compact_signature
            )
        ) {
            continue;
        }

        /*
         * 使用官方 ECDSA 验证函数进行最终检查。
         */
        if (
            secp256k1_ecdsa_verify(
                ctx,
                forged_signature,
                chosen_hash,
                victim_pubkey
            ) == 1
        ) {
            success = 1;
            break;
        }
    }

cleanup:
    BN_free(order);
    BN_free(half_order);

    BN_free(u_bn);
    BN_free(v_bn);
    BN_free(v_inverse);

    BN_free(r_bn);
    BN_free(s_bn);
    BN_free(e_bn);

    BN_CTX_free(bn_ctx);

    return success;
}

int main(void) {
    int exit_status = EXIT_FAILURE;

    secp256k1_context *ctx = NULL;

    unsigned char victim_seckey[32];
    secp256k1_pubkey victim_pubkey;

    const unsigned char real_message[] =
        "Pay Alice 1 BTC";

    unsigned char real_message_hash[32];
    unsigned char chosen_hash[32];

    secp256k1_ecdsa_signature normal_signature;
    secp256k1_ecdsa_signature forged_signature;

    unsigned char compact_forged_signature[64];

    int normal_result;
    int forged_result;
    int negative_control_result;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    if (ctx == NULL) {
        fprintf(stderr, "Failed to create secp256k1 context\n");
        goto cleanup;
    }

    /*
     * 为了模拟受害者，随机生成一个真实私钥。
     *
     * 这个私钥只用于创建受害者公钥和正常签名；
     * 后面的伪造函数不会接收该私钥。
     */
    if (!random_valid_scalar(ctx, victim_seckey)) {
        fprintf(stderr, "Failed to generate victim secret key\n");
        goto cleanup;
    }

    if (
        !secp256k1_ec_pubkey_create(
            ctx,
            &victim_pubkey,
            victim_seckey
        )
    ) {
        fprintf(stderr, "Failed to create victim public key\n");
        goto cleanup;
    }

    /*
     * 对真实消息计算 SHA-256。
     */
    if (
        SHA256(
            real_message,
            strlen((const char *) real_message),
            real_message_hash
        ) == NULL
    ) {
        fprintf(stderr, "SHA256 failed\n");
        goto cleanup;
    }

    printf("============================================\n");
    printf("ECDSA chosen-hash construction experiment\n");
    printf("libsecp256k1 official verification is used\n");
    printf("============================================\n\n");

    /*
     * 实验一：正常签名与验证。
     */
    printf("[1] Normal ECDSA signature\n");

    if (
        !secp256k1_ecdsa_sign(
            ctx,
            &normal_signature,
            real_message_hash,
            victim_seckey,
            NULL,
            NULL
        )
    ) {
        fprintf(stderr, "Normal ECDSA signing failed\n");
        goto cleanup;
    }

    normal_result = secp256k1_ecdsa_verify(
        ctx,
        &normal_signature,
        real_message_hash,
        &victim_pubkey
    );

    printf(
        "Normal signature verification: %s\n\n",
        normal_result == 1 ? "PASS" : "FAIL"
    );

    /*
     * 实验二：攻击者只使用公钥构造 e'、r'、s'。
     */
    printf("[2] Chosen-hash signature construction\n");
    printf(
        "The forging function receives only the public key, "
        "not the private key.\n"
    );

    if (
        !forge_chosen_hash_signature(
            ctx,
            &victim_pubkey,
            chosen_hash,
            &forged_signature
        )
    ) {
        fprintf(stderr, "Chosen-hash construction failed\n");
        goto cleanup;
    }

    forged_result = secp256k1_ecdsa_verify(
        ctx,
        &forged_signature,
        chosen_hash,
        &victim_pubkey
    );

    if (
        !secp256k1_ecdsa_signature_serialize_compact(
            ctx,
            compact_forged_signature,
            &forged_signature
        )
    ) {
        fprintf(stderr, "Failed to serialize forged signature\n");
        goto cleanup;
    }

    print_hex("Chosen digest e' : ", chosen_hash, 32);
    print_hex(
        "Forged r'        : ",
        compact_forged_signature,
        32
    );
    print_hex(
        "Forged s'        : ",
        compact_forged_signature + 32,
        32
    );

    printf(
        "Verification on chosen digest: %s\n\n",
        forged_result == 1 ? "PASS" : "FAIL"
    );

    /*
     * 实验三：把相同伪造签名用于真实消息摘要。
     *
     * 攻击者并没有控制真实消息的 SHA-256，
     * 因而验证应当失败。
     */
    printf("[3] Negative control using a real message\n");

    printf(
        "Message: %s\n",
        real_message
    );

    print_hex(
        "SHA256(message)   : ",
        real_message_hash,
        32
    );

    negative_control_result = secp256k1_ecdsa_verify(
        ctx,
        &forged_signature,
        real_message_hash,
        &victim_pubkey
    );

    printf(
        "Same signature on SHA256(message): %s\n\n",
        negative_control_result == 0 ? "FAIL (expected)" : "PASS (unexpected)"
    );

    /*
     * 正确的实验结果应为：
     *
     *   正常签名：PASS
     *   自选摘要构造：PASS
     *   真实消息对照：FAIL
     */
    if (
        normal_result == 1 &&
        forged_result == 1 &&
        negative_control_result == 0
    ) {
        printf("============================================\n");
        printf("Overall experiment result: PASS\n");
        printf("ECDSA itself was not broken.\n");
        printf(
            "The construction works only when an untrusted "
            "digest is accepted directly.\n"
        );
        printf("============================================\n");

        exit_status = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Unexpected experiment result\n");
    }

cleanup:
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
    }

    /*
     * 清除受害者私钥所在内存。
     */
    OPENSSL_cleanse(victim_seckey, sizeof(victim_seckey));

    return exit_status;
}
