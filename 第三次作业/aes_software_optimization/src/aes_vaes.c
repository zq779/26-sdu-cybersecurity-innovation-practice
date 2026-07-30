#include "aes_internal.h"
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#if defined(__GNUC__) || defined(__clang__)
#define TARGET_VAES __attribute__((target("vaes,avx2,aes")))
#else
#define TARGET_VAES
#endif
int aes_vaes_available(void){
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();return __builtin_cpu_supports("vaes")&&__builtin_cpu_supports("avx2")&&__builtin_cpu_supports("aes");
#else
    return 0;
#endif
}
TARGET_VAES static __m256i rk256(const uint8_t*p){return _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)p));}
TARGET_VAES void aes_vaes_encrypt_blocks(const aes_key_t*k,const uint8_t*in,uint8_t*out,size_t n){
    while(n>=4){__m256i a=_mm256_loadu_si256((const __m256i*)in),b=_mm256_loadu_si256((const __m256i*)(in+32)),rk=rk256(k->round_keys);a=_mm256_xor_si256(a,rk);b=_mm256_xor_si256(b,rk);
        for(int r=1;r<k->rounds;r++){rk=rk256(k->round_keys+16*r);a=_mm256_aesenc_epi128(a,rk);b=_mm256_aesenc_epi128(b,rk);}rk=rk256(k->round_keys+16*k->rounds);a=_mm256_aesenclast_epi128(a,rk);b=_mm256_aesenclast_epi128(b,rk);_mm256_storeu_si256((__m256i*)out,a);_mm256_storeu_si256((__m256i*)(out+32),b);in+=64;out+=64;n-=4;}
    while(n>=2){__m256i a=_mm256_loadu_si256((const __m256i*)in),rk=rk256(k->round_keys);a=_mm256_xor_si256(a,rk);for(int r=1;r<k->rounds;r++)a=_mm256_aesenc_epi128(a,rk256(k->round_keys+16*r));a=_mm256_aesenclast_epi128(a,rk256(k->round_keys+16*k->rounds));_mm256_storeu_si256((__m256i*)out,a);in+=32;out+=32;n-=2;}
    while(n--){aes_aesni_encrypt_block(k,in,out);in+=16;out+=16;}_mm256_zeroupper();
}
TARGET_VAES void aes_vaes_decrypt_blocks(const aes_key_t*k,const uint8_t*in,uint8_t*out,size_t n){
    while(n>=2){__m256i a=_mm256_loadu_si256((const __m256i*)in),rk=rk256(k->round_keys+16*k->rounds);a=_mm256_xor_si256(a,rk);for(int r=k->rounds-1;r>0;r--){__m128i x=_mm_aesimc_si128(_mm_loadu_si128((const __m128i*)(k->round_keys+16*r)));rk=_mm256_broadcastsi128_si256(x);a=_mm256_aesdec_epi128(a,rk);}a=_mm256_aesdeclast_epi128(a,rk256(k->round_keys));_mm256_storeu_si256((__m256i*)out,a);in+=32;out+=32;n-=2;}
    while(n--){aes_aesni_decrypt_block(k,in,out);in+=16;out+=16;}_mm256_zeroupper();
}
TARGET_VAES void aes_vaes_encrypt_block(const aes_key_t*k,const uint8_t in[16],uint8_t out[16]){aes_aesni_encrypt_block(k,in,out);} 
TARGET_VAES void aes_vaes_decrypt_block(const aes_key_t*k,const uint8_t in[16],uint8_t out[16]){aes_aesni_decrypt_block(k,in,out);} 
#else
int aes_vaes_available(void){return 0;}void aes_vaes_encrypt_block(const aes_key_t*k,const uint8_t i[16],uint8_t o[16]){aes_baseline_encrypt_block(k,i,o);}void aes_vaes_decrypt_block(const aes_key_t*k,const uint8_t i[16],uint8_t o[16]){aes_baseline_decrypt_block(k,i,o);}void aes_vaes_encrypt_blocks(const aes_key_t*k,const uint8_t*i,uint8_t*o,size_t n){aes_generic_encrypt_blocks(aes_baseline_encrypt_block,k,i,o,n);}void aes_vaes_decrypt_blocks(const aes_key_t*k,const uint8_t*i,uint8_t*o,size_t n){aes_generic_decrypt_blocks(aes_baseline_decrypt_block,k,i,o,n);}
#endif
