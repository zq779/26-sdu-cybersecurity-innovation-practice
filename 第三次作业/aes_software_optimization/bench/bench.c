#define _POSIX_C_SOURCE 200809L
#include "aeslab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_sec(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
static void fill(uint8_t*p,size_t n){uint32_t x=0x12345678;for(size_t i=0;i<n;i++){x^=x<<13;x^=x>>17;x^=x<<5;p[i]=(uint8_t)x;}}
static double mibps(size_t bytes,int iters,double sec){return ((double)bytes*iters/(1024.0*1024.0))/sec;}
static void print_result(int csv,const char *be,const char *mode,size_t bytes,int iters,double sec){if(csv)printf("%s,%s,%zu,%d,%.3f\n",be,mode,bytes,iters,mibps(bytes,iters,sec));else printf("%-9s %-5s %10.2f MiB/s\n",be,mode,mibps(bytes,iters,sec));}
int main(int argc,char**argv){
    size_t bytes=16u*1024u*1024u;int iters=8,csv=0;for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--bytes")&&i+1<argc)bytes=strtoull(argv[++i],0,0);else if(!strcmp(argv[i],"--iters")&&i+1<argc)iters=atoi(argv[++i]);else if(!strcmp(argv[i],"--csv"))csv=1;}
    bytes=(bytes/16)*16;if(bytes<16)bytes=16;uint8_t *in=NULL,*out=NULL;if(posix_memalign((void**)&in,64,bytes+64)||posix_memalign((void**)&out,64,bytes+64)){free(in);free(out);return 2;}fill(in,bytes+64);uint8_t keybuf[64],iv[16];fill(keybuf,sizeof keybuf);fill(iv,sizeof iv);aes_key_t k128,k256,x1,x2;aes_set_encrypt_key(&k128,keybuf,128);aes_set_encrypt_key(&k256,keybuf,256);aes_set_encrypt_key(&x1,keybuf,128);aes_set_encrypt_key(&x2,keybuf+16,128);
    if(csv)puts("backend,mode,bytes,iters,MiB_per_s");
    for(int b=0;b<AES_BACKEND_COUNT;b++){const aes_backend_t*be=aes_get_backend((aes_backend_id_t)b);if(!be->available())continue;double t0,t1;volatile uint8_t sink=0;
        t0=now_sec();for(int r=0;r<iters;r++){be->encrypt_blocks(&k128,in,out,bytes/16);sink^=out[r&15];}t1=now_sec();print_result(csv,be->name,"ECB",bytes,iters,t1-t0);
        t0=now_sec();for(int r=0;r<iters;r++){uint8_t c[16];memcpy(c,iv,16);aes_ctr_crypt(be,&k128,c,in,out,bytes);sink^=out[r&15];}t1=now_sec();print_result(csv,be->name,"CTR",bytes,iters,t1-t0);
        t0=now_sec();for(int r=0;r<iters;r++){uint8_t tag[16];aes_gcm_encrypt(be,&k128,iv,NULL,0,in,out,bytes,tag);sink^=tag[r&15];}t1=now_sec();print_result(csv,be->name,"GCM",bytes,iters,t1-t0);
        t0=now_sec();for(int r=0;r<iters;r++){aes_xts_encrypt(be,&x1,&x2,iv,in,out,bytes);sink^=out[r&15];}t1=now_sec();print_result(csv,be->name,"XTS",bytes,iters,t1-t0);
        (void)k256;(void)sink;
    }free(in);free(out);return 0;
}
