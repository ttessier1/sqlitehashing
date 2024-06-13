#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1



#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md2Context Md2Context, * Md2ContextPtr;

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md4Context Md4Context, * Md4ContextPtr;

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md5Context Md5Context, * Md5ContextPtr;

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha1Context Sha1Context, * Sha1ContextPtr;

#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha224Context Sha224Context, * Sha224ContextPtr;

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha256Context Sha256Context, * Sha256ContextPtr;

#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha384Context Sha384Context, * Sha384ContextPtr;

#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha512Context Sha512Context, * Sha512ContextPtr;

#endif

#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3224Context Sha3224Context, * Sha3224ContextPtr;
#endif
#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3256Context Sha3256Context, * Sha3256ContextPtr;
#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3384Context Sha3384Context, * Sha3384ContextPtr;
#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3512Context Sha3512Context, * Sha3512ContextPtr;
#endif
#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD128Context RipeMD128Context, * RipeMD128ContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD160Context RipeMD160Context, * RipeMD160ContextPtr; 
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD256Context RipeMD256Context, * RipeMD256ContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD320Context RipeMD320Context, * RipeMD320ContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2BContext Blake2BContext, * Blake2BContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2SContext Blake2SContext, * Blake2SContextPtr; 
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerContext TigerContext, * TigerContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake128Context Shake128Context, * Shake128ContextPtr; 
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake256Context Shake256Context, * Shake256ContextPtr;
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash64Context Siphash64Context, * Siphash64ContextPtr;
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash128Context Siphash128Context, * Siphash128ContextPtr;
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh224Context Lsh224Context, * Lsh224ContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh256Context Lsh256Context, * Lsh256ContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh384Context Lsh384Context, * Lsh384ContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh512Context Lsh512Context, * Lsh512ContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sm3Context Sm3Context, * Sm3ContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct whirlpoolContext WhirlpoolContext, * WhirlpoolContextPtr;
#endif

#ifdef __cplusplus


#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Md2ContextPtr Md2Initialize();
extern "C" void Md2Update(Md2ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md2Finalize(Md2ContextPtr context);

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Md4ContextPtr Md4Initialize();
extern "C" void Md4Update(Md4ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md4Finalize(Md4ContextPtr context);

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Md5ContextPtr Md5Initialize();
extern "C" void Md5Update(Md5ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md5Finalize(Md5ContextPtr context);

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha1ContextPtr Sha1Initialize();
extern "C" void Sha1Update(Sha1ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha1Finalize(Sha1ContextPtr context);

#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha224ContextPtr Sha224Initialize();
extern "C" void Sha224Update(Sha224ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha224Finalize(Sha224ContextPtr context);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha256ContextPtr Sha256Initialize();
extern "C" void Sha256Update(Sha256ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha256Finalize(Sha256ContextPtr context);

#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha384ContextPtr Sha384Initialize();
extern "C" void Sha384Update(Sha384ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha384Finalize(Sha384ContextPtr context);

#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha512ContextPtr Sha512Initialize();
extern "C" void Sha512Update(Sha512ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha512Finalize(Sha512ContextPtr context);

#endif


#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3224ContextPtr Sha3224Initialize();
extern "C" void Sha3224Update(Sha3224ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha3224Finalize(Sha3224ContextPtr context);

#endif

#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3256ContextPtr Sha3256Initialize();
extern "C" void Sha3256Update(Sha3256ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha3256Finalize(Sha3256ContextPtr context);

#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3384ContextPtr Sha3384Initialize();
extern "C" void Sha3384Update(Sha3384ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha3384Finalize(Sha3384ContextPtr context);

#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3512ContextPtr Sha3512Initialize();
extern "C" void Sha3512Update(Sha3512ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sha3512Finalize(Sha3512ContextPtr context);

#endif


#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD128ContextPtr RipeMD128Initialize();
extern "C" void RipeMD128Update(RipeMD128ContextPtr context, const char* message, unsigned int length);
extern "C" const char* RipeMD128Finalize(RipeMD128ContextPtr context);

#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD160ContextPtr RipeMD160Initialize();
extern "C" void RipeMD160Update(RipeMD160ContextPtr context, const char* message, unsigned int length);
extern "C" const char* RipeMD160Finalize(RipeMD160ContextPtr context);

#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD256ContextPtr RipeMD256Initialize();
extern "C" void RipeMD256Update(RipeMD256ContextPtr context, const char* message, unsigned int length);
extern "C" const char* RipeMD256Finalize(RipeMD256ContextPtr context);

#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD320ContextPtr RipeMD320Initialize();
extern "C" void RipeMD320Update(RipeMD320ContextPtr context, const char* message, unsigned int length);
extern "C" const char* RipeMD320Finalize(RipeMD320ContextPtr context);

#endif


#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Blake2BContextPtr Blake2BInitialize();
extern "C" void Blake2BUpdate(Blake2BContextPtr context, const char* message, unsigned int length);
extern "C" const char* Blake2BFinalize(Blake2BContextPtr context);

#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Blake2SContextPtr Blake2SInitialize();
extern "C" void Blake2SUpdate(Blake2SContextPtr context, const char* message, unsigned int length);
extern "C" const char* Blake2SFinalize(Blake2SContextPtr context);

#endif

#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" TigerContextPtr TigerInitialize();
extern "C" void TigerUpdate(TigerContextPtr context, const char* message, unsigned int length);
extern "C" const char* TigerFinalize(TigerContextPtr context);

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Shake128ContextPtr Shake128Initialize();
extern "C" void Shake128Update(Shake128ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Shake128Finalize(Shake128ContextPtr context);

#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Shake256ContextPtr Shake256Initialize();
extern "C" void Shake256Update(Shake256ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Shake256Finalize(Shake256ContextPtr context);

#endif


#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Siphash64ContextPtr Siphash64Initialize();
extern "C" void Siphash64Update(Siphash64ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Siphash64Finalize(Siphash64ContextPtr context);

#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Siphash128ContextPtr Siphash128Initialize();
extern "C" void Siphash128Update(Siphash128ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Siphash128Finalize(Siphash128ContextPtr context);

#endif

#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh224ContextPtr Lsh224Initialize();
extern "C" void Lsh224Update(Lsh224ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Lsh224Finalize(Lsh224ContextPtr context);

#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh256ContextPtr Lsh256Initialize();
extern "C" void Lsh256Update(Lsh256ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Lsh256Finalize(Lsh256ContextPtr context);

#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh384ContextPtr Lsh384Initialize();
extern "C" void Lsh384Update(Lsh384ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Lsh384Finalize(Lsh384ContextPtr context);

#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh512ContextPtr Lsh512Initialize();
extern "C" void Lsh512Update(Lsh512ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Lsh512Finalize(Lsh512ContextPtr context);

#endif

#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sm3ContextPtr Sm3Initialize();
extern "C" void Sm3Update(Sm3ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Sm3Finalize(Sm3ContextPtr context);

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" WhirlpoolContextPtr WhirlpoolInitialize();
extern "C" void WhirlpoolUpdate(WhirlpoolContextPtr context, const char* message, unsigned int length);
extern "C" const char* WhirlpoolFinalize(WhirlpoolContextPtr context);

#endif

#else
#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

Md2ContextPtr Md2Initialize();
void Md2Update(Md2ContextPtr context, const char* message, unsigned int length);
const char* Md2Finalize(Md2ContextPtr context);

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

Md4ContextPtr Md4Initialize();
void Md4Update(Md4ContextPtr context, const char* message, unsigned int length);
const char* Md4Finalize(Md4ContextPtr context);

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

Md5ContextPtr Md5Initialize();
void Md5Update(Md5ContextPtr context, const char* message, unsigned int length);
const char* Md5Finalize(Md5ContextPtr context);

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha1ContextPtr Sha1Initialize();
void Sha1Update(Sha1ContextPtr context, const char* message, unsigned int length);
const char* Sha1Finalize(Sha1ContextPtr context);

#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha224ContextPtr Sha224Initialize();
void Sha224Update(Sha224ContextPtr context, const char* message, unsigned int length);
const char* Sha224Finalize(Sha224ContextPtr context);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha256ContextPtr Sha256Initialize();
void Sha256Update(Sha256ContextPtr context, const char* message, unsigned int length);
const char* Sha256Finalize(Sha256ContextPtr context);

#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha384ContextPtr Sha384Initialize();
void Sha384Update(Sha384ContextPtr context, const char* message, unsigned int length);
const char* Sha384Finalize(Sha384ContextPtr context);

#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha512ContextPtr Sha512Initialize();
void Sha512Update(Sha512ContextPtr context, const char* message, unsigned int length);
const char* Sha512Finalize(Sha512ContextPtr context);

#endif

#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3224ContextPtr Sha3224Initialize();
void Sha3224Update(Sha3224ContextPtr context, const char* message, unsigned int length);
const char* Sha3224Finalize(Sha3224ContextPtr context);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha256ContextPtr Sha256Initialize();
void Sha256Update(Sha256ContextPtr context, const char* message, unsigned int length);
const char* Sha256Finalize(Sha256ContextPtr context);

#endif

#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3384ContextPtr Sha3384Initialize();
void Sha3384Update(Sha3384ContextPtr context, const char* message, unsigned int length);
const char* Sha3384Finalize(Sha3384ContextPtr context);

#endif

#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3512ContextPtr Sha3512Initialize();
void Sha3512Update(Sha3512ContextPtr context, const char* message, unsigned int length);
const char* Sha3512Finalize(Sha3512ContextPtr context);

#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD128ContextPtr RipeMD128Initialize();
void RipeMD128Update(RipeMD128ContextPtr context, const char* message, unsigned int length);
const char* RipeMD128Finalize(RipeMD128ContextPtr context);

#endif

#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD160ContextPtr RipeMD160Initialize();
void RipeMD160Update(RipeMD160ContextPtr context, const char* message, unsigned int length);
const char* RipeMD160Finalize(RipeMD160ContextPtr context);

#endif

#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD256ContextPtr RipeMD256Initialize();
void RipeMD256Update(RipeMD256ContextPtr context, const char* message, unsigned int length);
const char* RipeMD256Finalize(RipeMD256ContextPtr context);

#endif

#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD320ContextPtr RipeMD320Initialize();
void RipeMD320Update(RipeMD320ContextPtr context, const char* message, unsigned int length);
const char* RipeMD320Finalize(RipeMD320ContextPtr context);

#endif

#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)

Blake2BContextPtr Blake2BInitialize();
void Blake2BUpdate(Blake2BContextPtr context, const char* message, unsigned int length);
const char* Blake2BFinalize(Blake2BContextPtr context);

#endif

#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)

Blake2SContextPtr Blake2SInitialize();
void Blake2SUpdate(Blake2SContextPtr context, const char* message, unsigned int length);
const char* Blake2SFinalize(Blake2SContextPtr context);

#endif

#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)

TigerContextPtr TigerInitialize();
void TigerUpdate(TigerContextPtr context, const char* message, unsigned int length);
const char* TigerFinalize(TigerContextPtr context);

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)

Shake128ContextPtr Shake128Initialize();
void Shake128Update(Shake128ContextPtr context, const char* message, unsigned int length);
const char* Shake128Finalize(Shake128ContextPtr context);

#endif

#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Shake256ContextPtr Shake256Initialize();
void Shake256Update(Shake256ContextPtr context, const char* message, unsigned int length);
const char* Shake256Finalize(Shake256ContextPtr context);

#endif

#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)

Siphash64ContextPtr Siphash64Initialize();
void Siphash64Update(Siphash64ContextPtr context, const char* message, unsigned int length);
const char* Siphash64Finalize(Siphash64ContextPtr context);

#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)

Siphash128ContextPtr Siphash128Initialize();
void Siphash128Update(Siphash128ContextPtr context, const char* message, unsigned int length);
const char* Siphash128Finalize(Siphash128ContextPtr context);

#endif

#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh224ContextPtr Lsh224Initialize();
void Lsh224Update(Lsh224ContextPtr context, const char* message, unsigned int length);
const char* Lsh224Finalize(Lsh224ContextPtr context);

#endif

#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh256ContextPtr Lsh256Initialize();
void Lsh256Update(Lsh256ContextPtr context, const char* message, unsigned int length);
const char* Lsh256Finalize(Lsh256ContextPtr context);

#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh384ContextPtr Lsh384Initialize();
void Lsh384Update(Lsh384ContextPtr context, const char* message, unsigned int length);
const char* Lsh384Finalize(Lsh384ContextPtr context);

#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh512ContextPtr Lsh512Initialize();
void Lsh512Update(Lsh512ContextPtr context, const char* message, unsigned int length);
const char* Lsh512Finalize(Lsh512ContextPtr context);

#endif

#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sm3ContextPtr Sm3Initialize();
void Sm3Update(Sm3ContextPtr context, const char* message, unsigned int length);
const char* Sm3Finalize(Sm3ContextPtr context);

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)

WhirlpoolContextPtr WhirlpoolInitialize();
void WhirlpoolUpdate(WhirlpoolContextPtr context, const char* message, unsigned int length);
const char* WhirlpoolFinalize(WhirlpoolContextPtr context);

#endif


#endif