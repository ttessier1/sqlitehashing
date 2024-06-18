#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md2BlobContext Md2BlobContext, * Md2BlobContextPtr;

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md4BlobContext Md4BlobContext, * Md4BlobContextPtr;

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct md5BlobContext Md5BlobContext, * Md5BlobContextPtr;

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha1BlobContext Sha1BlobContext, * Sha1BlobContextPtr;

#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha224BlobContext Sha224BlobContext, * Sha224BlobContextPtr;

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha256BlobContext Sha256BlobContext, * Sha256BlobContextPtr;

#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha384BlobContext Sha384BlobContext, * Sha384BlobContextPtr;

#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)

typedef struct sha512BlobContext Sha512BlobContext, * Sha512BlobContextPtr;

#endif

#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3224BlobContext Sha3224BlobContext, * Sha3224BlobContextPtr;
#endif
#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3256BlobContext Sha3256BlobContext, * Sha3256BlobContextPtr;
#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3384BlobContext Sha3384BlobContext, * Sha3384BlobContextPtr;
#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3512BlobContext Sha3512BlobContext, * Sha3512BlobContextPtr;
#endif
#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD128BlobContext RipeMD128BlobContext, * RipeMD128BlobContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD160BlobContext RipeMD160BlobContext, * RipeMD160BlobContextPtr; 
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD256BlobContext RipeMD256BlobContext, * RipeMD256BlobContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD320BlobContext RipeMD320BlobContext, * RipeMD320BlobContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2BBlobContext Blake2BBlobContext, * Blake2BBlobContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2SBlobContext Blake2SBlobContext, * Blake2SBlobContextPtr; 
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerBlobContext TigerBlobContext, * TigerBlobContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake128BlobContext Shake128BlobContext, * Shake128BlobContextPtr; 
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake256BlobContext Shake256BlobContext, * Shake256BlobContextPtr;
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash64BlobContext Siphash64BlobContext, * Siphash64BlobContextPtr;
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash128BlobContext Siphash128BlobContext, * Siphash128BlobContextPtr;
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh224BlobContext Lsh224BlobContext, * Lsh224BlobContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh256BlobContext Lsh256BlobContext, * Lsh256BlobContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh384BlobContext Lsh384BlobContext, * Lsh384BlobContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh512BlobContext Lsh512BlobContext, * Lsh512BlobContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sm3BlobContext Sm3BlobContext, * Sm3BlobContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct whirlpoolBlobContext WhirlpoolBlobContext, * WhirlpoolBlobContextPtr;
#endif



#ifdef __cplusplus


#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Md2BlobContextPtr Md2Initialize();
extern "C" void Md2Update(Md2BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Md2Finalize(Md2BlobContextPtr blobContext);

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Md4BlobContextPtr Md4Initialize();
extern "C" void Md4Update(Md4BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Md4Finalize(Md4BlobContextPtr blobContext);

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Md5BlobContextPtr Md5Initialize();
extern "C" void Md5Update(Md5BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Md5Finalize(Md5BlobContextPtr blobContext);

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha1BlobContextPtr Sha1Initialize();
extern "C" void Sha1Update(Sha1BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha1Finalize(Sha1BlobContextPtr blobContext);

#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha224BlobContextPtr Sha224Initialize();
extern "C" void Sha224Update(Sha224BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha224Finalize(Sha224BlobContextPtr blobContext);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha256BlobContextPtr Sha256Initialize();
extern "C" void Sha256Update(Sha256BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha256Finalize(Sha256BlobContextPtr blobContext);

#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha384BlobContextPtr Sha384Initialize();
extern "C" void Sha384Update(Sha384BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha384Finalize(Sha384BlobContextPtr blobContext);

#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha512BlobContextPtr Sha512Initialize();
extern "C" void Sha512Update(Sha512BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha512Finalize(Sha512BlobContextPtr blobContext);

#endif


#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3224BlobContextPtr Sha3224Initialize();
extern "C" void Sha3224Update(Sha3224BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha3224Finalize(Sha3224BlobContextPtr blobContext);

#endif

#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3256BlobContextPtr Sha3256Initialize();
extern "C" void Sha3256Update(Sha3256BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha3256Finalize(Sha3256BlobContextPtr blobContext);

#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3384BlobContextPtr Sha3384Initialize();
extern "C" void Sha3384Update(Sha3384BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha3384Finalize(Sha3384BlobContextPtr blobContext);

#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sha3512BlobContextPtr Sha3512Initialize();
extern "C" void Sha3512Update(Sha3512BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sha3512Finalize(Sha3512BlobContextPtr blobContext);

#endif


#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD128BlobContextPtr RipeMD128Initialize();
extern "C" void RipeMD128Update(RipeMD128BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD128Finalize(RipeMD128BlobContextPtr blobContext);

#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD160BlobContextPtr RipeMD160Initialize();
extern "C" void RipeMD160Update(RipeMD160BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD160Finalize(RipeMD160BlobContextPtr blobContext);

#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD256BlobContextPtr RipeMD256Initialize();
extern "C" void RipeMD256Update(RipeMD256BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD256Finalize(RipeMD256BlobContextPtr blobContext);

#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" RipeMD320BlobContextPtr RipeMD320Initialize();
extern "C" void RipeMD320Update(RipeMD320BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD320Finalize(RipeMD320BlobContextPtr blobContext);

#endif


#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Blake2BBlobContextPtr Blake2BInitialize();
extern "C" void Blake2BUpdate(Blake2BBlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Blake2BFinalize(Blake2BBlobContextPtr blobContext);

#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Blake2SBlobContextPtr Blake2SInitialize();
extern "C" void Blake2SUpdate(Blake2SBlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Blake2SFinalize(Blake2SBlobContextPtr blobContext);

#endif

#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" TigerBlobContextPtr TigerInitialize();
extern "C" void TigerUpdate(TigerBlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* TigerFinalize(TigerBlobContextPtr blobContext);

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Shake128BlobContextPtr Shake128Initialize();
extern "C" void Shake128Update(Shake128BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Shake128Finalize(Shake128BlobContextPtr blobContext);

#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Shake256BlobContextPtr Shake256Initialize();
extern "C" void Shake256Update(Shake256BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Shake256Finalize(Shake256BlobContextPtr blobContext);

#endif


#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Siphash64BlobContextPtr Siphash64Initialize();
extern "C" void Siphash64Update(Siphash64BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Siphash64Finalize(Siphash64BlobContextPtr blobContext);

#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Siphash128BlobContextPtr Siphash128Initialize();
extern "C" void Siphash128Update(Siphash128BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Siphash128Finalize(Siphash128BlobContextPtr blobContext);

#endif

#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh224BlobContextPtr Lsh224Initialize();
extern "C" void Lsh224Update(Lsh224BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Lsh224Finalize(Lsh224BlobContextPtr blobContext);

#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh256BlobContextPtr Lsh256Initialize();
extern "C" void Lsh256Update(Lsh256BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Lsh256Finalize(Lsh256BlobContextPtr blobContext);

#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh384BlobContextPtr Lsh384Initialize();
extern "C" void Lsh384Update(Lsh384BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Lsh384Finalize(Lsh384BlobContextPtr blobContext);

#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Lsh512BlobContextPtr Lsh512Initialize();
extern "C" void Lsh512Update(Lsh512BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Lsh512Finalize(Lsh512BlobContextPtr blobContext);

#endif

#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" Sm3BlobContextPtr Sm3Initialize();
extern "C" void Sm3Update(Sm3BlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* Sm3Finalize(Sm3BlobContextPtr blobContext);

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)

extern "C" WhirlpoolBlobContextPtr WhirlpoolInitialize();
extern "C" void WhirlpoolUpdate(WhirlpoolBlobContextPtr blobContext, const char* message, unsigned int length);
extern "C" const char* WhirlpoolFinalize(WhirlpoolBlobContextPtr blobContext);

#endif

#else
#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)

Md2BlobContextPtr Md2Initialize();
void Md2Update(Md2BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Md2Finalize(Md2BlobContextPtr blobContext);

#endif

#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)

Md4BlobContextPtr Md4Initialize();
void Md4Update(Md4BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Md4Finalize(Md4BlobContextPtr blobContext);

#endif

#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)

Md5BlobContextPtr Md5Initialize();
void Md5Update(Md5BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Md5Finalize(Md5BlobContextPtr blobContext);

#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha1BlobContextPtr Sha1Initialize();
void Sha1Update(Sha1BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha1Finalize(Sha1BlobContextPtr blobContext);

#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha224BlobContextPtr Sha224Initialize();
void Sha224Update(Sha224BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha224Finalize(Sha224BlobContextPtr blobContext);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha256BlobContextPtr Sha256Initialize();
void Sha256Update(Sha256BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha256Finalize(Sha256BlobContextPtr blobContext);

#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha384BlobContextPtr Sha384Initialize();
void Sha384Update(Sha384BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha384Finalize(Sha384BlobContextPtr blobContext);

#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha512BlobContextPtr Sha512Initialize();
void Sha512Update(Sha512BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha512Finalize(Sha512BlobContextPtr blobContext);

#endif

#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3224BlobContextPtr Sha3224Initialize();
void Sha3224Update(Sha3224BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha3224Finalize(Sha3224BlobContextPtr blobContext);

#endif

#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3256BlobContextPtr Sha3256Initialize();
void Sha3256Update(Sha3256BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha3256Finalize(Sha3256BlobContextPtr blobContext);

#endif

#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3384BlobContextPtr Sha3384Initialize();
void Sha3384Update(Sha3384BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha3384Finalize(Sha3384BlobContextPtr blobContext);

#endif

#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sha3512BlobContextPtr Sha3512Initialize();
void Sha3512Update(Sha3512BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sha3512Finalize(Sha3512BlobContextPtr blobContext);

#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD128BlobContextPtr RipeMD128Initialize();
void RipeMD128Update(RipeMD128BlobContextPtr blobContext, const char* message, unsigned int length);
const char* RipeMD128Finalize(RipeMD128BlobContextPtr blobContext);

#endif

#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD160BlobContextPtr RipeMD160Initialize();
void RipeMD160Update(RipeMD160BlobContextPtr blobContext, const char* message, unsigned int length);
const char* RipeMD160Finalize(RipeMD160BlobContextPtr blobContext);

#endif

#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD256BlobContextPtr RipeMD256Initialize();
void RipeMD256Update(RipeMD256BlobContextPtr blobContext, const char* message, unsigned int length);
const char* RipeMD256Finalize(RipeMD256BlobContextPtr blobContext);

#endif

#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)

RipeMD320BlobContextPtr RipeMD320Initialize();
void RipeMD320Update(RipeMD320BlobContextPtr blobContext, const char* message, unsigned int length);
const char* RipeMD320Finalize(RipeMD320BlobContextPtr blobContext);

#endif

#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)

Blake2BBlobContextPtr Blake2BInitialize();
void Blake2BUpdate(Blake2BBlobContextPtr blobContext, const char* message, unsigned int length);
const char* Blake2BFinalize(Blake2BBlobContextPtr blobContext);

#endif

#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)

Blake2SBlobContextPtr Blake2SInitialize();
void Blake2SUpdate(Blake2SBlobContextPtr blobContext, const char* message, unsigned int length);
const char* Blake2SFinalize(Blake2SBlobContextPtr blobContext);

#endif

#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)

TigerBlobContextPtr TigerInitialize();
void TigerUpdate(TigerBlobContextPtr blobContext, const char* message, unsigned int length);
const char* TigerFinalize(TigerBlobContextPtr blobContext);

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)

Shake128BlobContextPtr Shake128Initialize();
void Shake128Update(Shake128BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Shake128Finalize(Shake128BlobContextPtr blobContext);

#endif

#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Shake256BlobContextPtr Shake256Initialize();
void Shake256Update(Shake256BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Shake256Finalize(Shake256BlobContextPtr blobContext);

#endif

#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)

Siphash64BlobContextPtr Siphash64Initialize();
void Siphash64Update(Siphash64BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Siphash64Finalize(Siphash64BlobContextPtr blobContext);

#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)

Siphash128BlobContextPtr Siphash128Initialize();
void Siphash128Update(Siphash128BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Siphash128Finalize(Siphash128BlobContextPtr blobContext);

#endif

#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh224BlobContextPtr Lsh224Initialize();
void Lsh224Update(Lsh224BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Lsh224Finalize(Lsh224BlobContextPtr blobContext);

#endif

#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh256BlobContextPtr Lsh256Initialize();
void Lsh256Update(Lsh256BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Lsh256Finalize(Lsh256BlobContextPtr blobContext);

#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh384BlobContextPtr Lsh384Initialize();
void Lsh384Update(Lsh384BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Lsh384Finalize(Lsh384BlobContextPtr blobContext);

#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)

Lsh512BlobContextPtr Lsh512Initialize();
void Lsh512Update(Lsh512BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Lsh512Finalize(Lsh512BlobContextPtr blobContext);

#endif

#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)

Sm3BlobContextPtr Sm3Initialize();
void Sm3Update(Sm3BlobContextPtr blobContext, const char* message, unsigned int length);
const char* Sm3Finalize(Sm3BlobContextPtr blobContext);

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)

WhirlpoolBlobContextPtr WhirlpoolInitialize();
void WhirlpoolUpdate(WhirlpoolBlobContextPtr blobContext, const char* message, unsigned int length);
const char* WhirlpoolFinalize(WhirlpoolBlobContextPtr blobContext);

#endif


#endif