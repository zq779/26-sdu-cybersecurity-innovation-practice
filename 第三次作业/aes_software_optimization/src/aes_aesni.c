#include "aes_internal.h"
#if defined(__x86_64__) || defined(__i386__)
#include <wmmintrin.h>
#if defined(__GNUC__) || defined(__clang__)
#define TARGET_AES __attribute__((target("aes,sse2")))
#else
#define TARGET_AES
#endif
int aes_aesni_available(void){
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();return __builtin_cpu_supports("aes");
#else
    return 1;
#endif
}
TARGET_AES static __m128i enc1(const aes_key_t*k,__m128i s){
    s=_mm_xor_si128(s,_mm_loadu_si128((const __m128i*)k->round_keys));
    for(int r=1;r<k->rounds;r++)s=_mm_aesenc_si128(s,_mm_loadu_si128((const __m128i*)(k->round_keys+16*r)));
    return _mm_aesenclast_si128(s,_mm_loadu_si128((const __m128i*)(k->round_keys+16*k->rounds)));
}
TARGET_AES static __m128i dec1(const aes_key_t*k,__m128i s){
    s=_mm_xor_si128(s,_mm_loadu_si128((const __m128i*)(k->round_keys+16*k->rounds)));
    for(int r=k->rounds-1;r>0;r--)s=_mm_aesdec_si128(s,_mm_aesimc_si128(_mm_loadu_si128((const __m128i*)(k->round_keys+16*r))));
    return _mm_aesdeclast_si128(s,_mm_loadu_si128((const __m128i*)k->round_keys));
}
TARGET_AES void aes_aesni_encrypt_block(const aes_key_t*k,const uint8_t in[16],uint8_t out[16]){_mm_storeu_si128((__m128i*)out,enc1(k,_mm_loadu_si128((const __m128i*)in)));}
TARGET_AES void aes_aesni_decrypt_block(const aes_key_t*k,const uint8_t in[16],uint8_t out[16]){_mm_storeu_si128((__m128i*)out,dec1(k,_mm_loadu_si128((const __m128i*)in)));}
TARGET_AES void aes_aesni_encrypt_blocks(const aes_key_t*k,const uint8_t*in,uint8_t*out,size_t n){
    while(n>=4){__m128i a=_mm_loadu_si128((const __m128i*)in),b=_mm_loadu_si128((const __m128i*)(in+16)),c=_mm_loadu_si128((const __m128i*)(in+32)),d=_mm_loadu_si128((const __m128i*)(in+48));
        __m128i rk=_mm_loadu_si128((const __m128i*)k->round_keys);a=_mm_xor_si128(a,rk);b=_mm_xor_si128(b,rk);c=_mm_xor_si128(c,rk);d=_mm_xor_si128(d,rk);
        for(int r=1;r<k->rounds;r++){rk=_mm_loadu_si128((const __m128i*)(k->round_keys+16*r));a=_mm_aesenc_si128(a,rk);b=_mm_aesenc_si128(b,rk);c=_mm_aesenc_si128(c,rk);d=_mm_aesenc_si128(d,rk);}rk=_mm_loadu_si128((const __m128i*)(k->round_keys+16*k->rounds));a=_mm_aesenclast_si128(a,rk);b=_mm_aesenclast_si128(b,rk);c=_mm_aesenclast_si128(c,rk);d=_mm_aesenclast_si128(d,rk);
        _mm_storeu_si128((__m128i*)out,a);_mm_storeu_si128((__m128i*)(out+16),b);_mm_storeu_si128((__m128i*)(out+32),c);_mm_storeu_si128((__m128i*)(out+48),d);in+=64;out+=64;n-=4;}
    while(n--){aes_aesni_encrypt_block(k,in,out);in+=16;out+=16;}
}
TARGET_AES void aes_aesni_decrypt_blocks(const aes_key_t*k,const uint8_t*in,uint8_t*out,size_t n){while(n--){aes_aesni_decrypt_block(k,in,out);in+=16;out+=16;}}
#else
int aes_aesni_available(void){return 0;}
void aes_aesni_encrypt_block(const aes_key_t*k,const uint8_t i[16],uint8_t o[16]){aes_baseline_encrypt_block(k,i,o);}void aes_aesni_decrypt_block(const aes_key_t*k,const uint8_t i[16],uint8_t o[16]){aes_baseline_decrypt_block(k,i,o);}void aes_aesni_encrypt_blocks(const aes_key_t*k,const uint8_t*i,uint8_t*o,size_t n){aes_generic_encrypt_blocks(aes_baseline_encrypt_block,k,i,o,n);}void aes_aesni_decrypt_blocks(const aes_key_t*k,const uint8_t*i,uint8_t*o,size_t n){aes_generic_decrypt_blocks(aes_baseline_decrypt_block,k,i,o,n);}
#endif
