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
typedef struct tigerContext TigerContext, * TigerContextPtr; 
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerContext TigerContext, * TigerContextPtr;
#endif
/*
#if defined(__SIPHASH64__) || defined (__ALL__)
        hash_function_siphash64,
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_siphash64blob,
#endif
#if defined(__SIPHASH128__) || defined (__ALL__)
        hash_function_siphash128,
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_siphash128blob,
#endif
#if defined(__LSH224__) || defined (__ALL__)
        hash_function_lsh224,
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_lsh224blob,
#endif
#if defined(__LSH256__) || defined (__ALL__)
        hash_function_lsh256,
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_lsh256blob,
#endif
#if defined(__LSH384__) || defined (__ALL__)
        hash_function_lsh384,
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_lsh384blob,
#endif
#if defined(__LSH512__) || defined (__ALL__)
        hash_function_lsh512,
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_lsh512blob,
#endif
#if defined(__SM3__) || defined (__ALL__)
        hash_function_sm3,
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_sm3blob,
#endif
#if defined(__WHIRLPOOL__) || defined (__ALL__)
        hash_function_whirlpool,
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_whirlpoolblob,
#endif
*/

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

#endif