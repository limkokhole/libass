/* Copyright 2020 王一 Wang Yi <godspeed_china@yeah.net>
   This is free and unencumbered software released into the public domain. http://unlicense.org/
   See github.com/wangyi-fudan/wyhash/LICENSE
 */
#ifndef wyhash_final_version_2
#define wyhash_final_version_2
//defines that change behavior
#ifndef WYHASH_CONDOM
#define WYHASH_CONDOM 1 //0: read 8 bytes before and after boundaries, dangerous but fastest. 1: normal valid behavior 2: extra protection against entropy loss (probability=2^-63), aka. "blind multiplication"
#endif
#define WYHASH_32BIT_MUM 0	//faster on 32 bit system
//includes
#include <stdint.h>
#include <string.h>
#if defined(_MSC_VER) && defined(_M_X64)
  #include <intrin.h>
  #pragma intrinsic(_umul128)
#endif
#if defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
  #define _likely_(x)	__builtin_expect(x,1)
  #define _unlikely_(x)	__builtin_expect(x,0)
#else
  #define _likely_(x) (x)
  #define _unlikely_(x) (x)
#endif
//mum function
static inline uint64_t _wyrot(uint64_t x) { return (x>>32)|(x<<32); }
static inline void _wymum(uint64_t *A, uint64_t *B){
#if(WYHASH_32BIT_MUM)
  uint64_t hh=(*A>>32)*(*B>>32), hl=(*A>>32)*(unsigned)*B, lh=(unsigned)*A*(*B>>32), ll=(uint64_t)(unsigned)*A*(unsigned)*B;
  #if(WYHASH_CONDOM>1)
  *A^=_wyrot(hl)^hh; *B^=_wyrot(lh)^ll;
  #else
  *A=_wyrot(hl)^hh; *B=_wyrot(lh)^ll;
  #endif
#elif defined(__SIZEOF_INT128__)
  __uint128_t r=*A; r*=*B;
  #if(WYHASH_CONDOM>1)
  *A^=(uint64_t)r; *B^=(uint64_t)(r>>64);
  #else
  *A=(uint64_t)r; *B=(uint64_t)(r>>64);
  #endif
#elif defined(_MSC_VER) && defined(_M_X64)
  #if(WYHASH_CONDOM>1)
  uint64_t  a,  b;
  a=_umul128(*A,*B,&b);
  *A^=a;  *B^=b;
  #else
  *A=_umul128(*A,*B,B);
  #endif
#else
  uint64_t ha=*A>>32, hb=*B>>32, la=(uint32_t)*A, lb=(uint32_t)*B, hi, lo;
  uint64_t rh=ha*hb, rm0=ha*lb, rm1=hb*la, rl=la*lb, t=rl+(rm0<<32), c=t<rl;
  lo=t+(rm1<<32); c+=lo<t; hi=rh+(rm0>>32)+(rm1>>32)+c;
  #if(WYHASH_CONDOM>1)
  *A^=lo;  *B^=hi;
  #else
  *A=lo;  *B=hi;
  #endif
#endif
}
static inline uint64_t _wymix(uint64_t A, uint64_t B){ _wymum(&A,&B); return A^B; }
//read functions
#ifndef WYHASH_LITTLE_ENDIAN
  #if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define WYHASH_LITTLE_ENDIAN 1
  #elif defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    #define WYHASH_LITTLE_ENDIAN 0
  #endif
#endif
#if (WYHASH_LITTLE_ENDIAN)
static inline uint64_t _wyr8(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v;}
static inline uint64_t _wyr4(const uint8_t *p) { unsigned v; memcpy(&v, p, 4); return v;}
#elif defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
static inline uint64_t _wyr8(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return __builtin_bswap64(v);}
static inline uint64_t _wyr4(const uint8_t *p) { unsigned v; memcpy(&v, p, 4); return __builtin_bswap32(v);}
#elif defined(_MSC_VER)
static inline uint64_t _wyr8(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return _byteswap_uint64(v);}
static inline uint64_t _wyr4(const uint8_t *p) { unsigned v; memcpy(&v, p, 4); return _byteswap_ulong(v);}
#endif
static inline uint64_t _wyr3(const uint8_t *p, unsigned k) { return (((uint64_t)p[0])<<16)|(((uint64_t)p[k>>1])<<8)|p[k-1];}
//wyhash function
static inline uint64_t wyhash(const void *key, uint64_t len, uint64_t seed, const uint64_t *secret){
  const uint8_t *p=(const uint8_t *)key;  uint64_t a,b; seed^=*secret;
  if(_likely_(len<=16)){
#if(WYHASH_CONDOM>0)
    if(_likely_(len<=8)){
      if(_likely_(len>=4)){ a=_wyr4(p); b=_wyr4(p+len-4); }
      else if (_likely_(len)){ a=_wyr3(p,len); b=0; }
      else a=b=0;
    }
    else{ a=_wyr8(p); b=_wyr8(p+len-8); }
#else
    uint64_t s=(len<8)*((8-len)<<3);
    a=_wyr8(p)<<s;	b=_wyr8(p+len-8)>>s;
#endif
  }
  else{
    uint64_t i=len;
    if(_unlikely_(i>48)){
      uint64_t see1=seed, see2=seed;
      do{
        seed=_wymix(_wyr8(p)^secret[1],_wyr8(p+8)^seed);
        see1=_wymix(_wyr8(p+16)^secret[2],_wyr8(p+24)^see1);
        see2=_wymix(_wyr8(p+32)^secret[3],_wyr8(p+40)^see2);
        p+=48; i-=48;
      }while(i>48);
      seed^=see1^see2;
    }
    while(_unlikely_(i>16)){	seed=_wymix(_wyr8(p)^secret[1],_wyr8(p+8)^seed);	i-=16; p+=16;	}
    a=_wyr8(p+i-16); b=_wyr8(p+i-8);
  }
  return _wymix(secret[1]^len,_wymix(a^secret[1], b^seed));
}
#endif
