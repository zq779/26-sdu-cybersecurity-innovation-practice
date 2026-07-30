#include "aes_internal.h"
#include <stdatomic.h>

static uint32_t Te[4][256], Td[4][256];
static atomic_int tables_ready = 0;
static atomic_flag tables_lock = ATOMIC_FLAG_INIT;

static uint32_t pack4(uint8_t a,uint8_t b,uint8_t c,uint8_t d){return (uint32_t)a|((uint32_t)b<<8)|((uint32_t)c<<16)|((uint32_t)d<<24);} 
static void init_tables(void){
    if(atomic_load_explicit(&tables_ready,memory_order_acquire)) return;
    while(atomic_flag_test_and_set_explicit(&tables_lock,memory_order_acquire)){}
    if(!atomic_load_explicit(&tables_ready,memory_order_relaxed)){
        for(int x=0;x<256;x++){
            uint8_t s=aes_sbox[x], s2=aes_gfmul(s,2), s3=(uint8_t)(s2^s);
            Te[0][x]=pack4(s2,s,s,s3); Te[1][x]=pack4(s3,s2,s,s);
            Te[2][x]=pack4(s,s3,s2,s); Te[3][x]=pack4(s,s,s3,s2);
            uint8_t q=aes_inv_sbox[x];
            Td[0][x]=pack4(aes_gfmul(q,14),aes_gfmul(q,9),aes_gfmul(q,13),aes_gfmul(q,11));
            Td[1][x]=pack4(aes_gfmul(q,11),aes_gfmul(q,14),aes_gfmul(q,9),aes_gfmul(q,13));
            Td[2][x]=pack4(aes_gfmul(q,13),aes_gfmul(q,11),aes_gfmul(q,14),aes_gfmul(q,9));
            Td[3][x]=pack4(aes_gfmul(q,9),aes_gfmul(q,13),aes_gfmul(q,11),aes_gfmul(q,14));
        }
        atomic_store_explicit(&tables_ready,1,memory_order_release);
    }
    atomic_flag_clear_explicit(&tables_lock,memory_order_release);
}
void aes_ttable_encrypt_block(const aes_key_t *k,const uint8_t in[16],uint8_t out[16]){
    init_tables(); uint8_t s[16],t[16]; for(int i=0;i<16;i++)s[i]=in[i]^k->round_keys[i];
    for(int r=1;r<k->rounds;r++){
        for(int c=0;c<4;c++){
            uint32_t w=Te[0][s[4*c]]^Te[1][s[4*((c+1)&3)+1]]^Te[2][s[4*((c+2)&3)+2]]^Te[3][s[4*((c+3)&3)+3]]^load32_le(k->round_keys+16*r+4*c);
            store32_le(t+4*c,w);
        } memcpy(s,t,16);
    }
    for(int r=0;r<4;r++)for(int c=0;c<4;c++)t[4*c+r]=(uint8_t)(aes_sbox[s[4*((c+r)&3)+r]]^k->round_keys[16*k->rounds+4*c+r]);
    memcpy(out,t,16);
}
void aes_ttable_decrypt_block(const aes_key_t *k,const uint8_t in[16],uint8_t out[16]){
    init_tables(); uint8_t s[16],t[16]; const uint8_t *last=k->round_keys+16*k->rounds;
    for(int i=0;i<16;i++)s[i]=in[i]^last[i];
    for(int r=k->rounds-1;r>0;r--){
        for(int c=0;c<4;c++){
            const uint8_t *q=k->round_keys+16*r+4*c;
            uint32_t ik=pack4(
                (uint8_t)(aes_gfmul(q[0],14)^aes_gfmul(q[1],11)^aes_gfmul(q[2],13)^aes_gfmul(q[3],9)),
                (uint8_t)(aes_gfmul(q[0],9)^aes_gfmul(q[1],14)^aes_gfmul(q[2],11)^aes_gfmul(q[3],13)),
                (uint8_t)(aes_gfmul(q[0],13)^aes_gfmul(q[1],9)^aes_gfmul(q[2],14)^aes_gfmul(q[3],11)),
                (uint8_t)(aes_gfmul(q[0],11)^aes_gfmul(q[1],13)^aes_gfmul(q[2],9)^aes_gfmul(q[3],14)));
            uint32_t w=Td[0][s[4*c]]^Td[1][s[4*((c+3)&3)+1]]^Td[2][s[4*((c+2)&3)+2]]^Td[3][s[4*((c+1)&3)+3]]^ik;
            store32_le(t+4*c,w);
        } memcpy(s,t,16);
    }
    for(int r=0;r<4;r++)for(int c=0;c<4;c++)t[4*c+r]=(uint8_t)(aes_inv_sbox[s[4*((c-r)&3)+r]]^k->round_keys[4*c+r]);
    memcpy(out,t,16);
}
