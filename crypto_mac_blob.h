#pragma once


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1


#if (defined(__MD2__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct md2MacBlobContext Md2MacBlobContext, * Md2MacBlobContextPtr;

#endif

#if (defined(__MD4__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct md4MacBlobContext Md4MacBlobContext, * Md4MacBlobContextPtr;

#endif

#if (defined(__MD5__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct md5MacBlobContext Md5MacBlobContext, * Md5MacBlobContextPtr;

#endif

#if (defined(__SHA1__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct sha1MacBlobContext Sha1MacBlobContext, * Sha1MacBlobContextPtr;

#endif

#if (defined(__SHA224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct sha224MacBlobContext Sha224MacBlobContext, * Sha224MacBlobContextPtr;

#endif

#if (defined(__SHA256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct sha256MacBlobContext Sha256MacBlobContext, * Sha256MacBlobContextPtr;

#endif

#if (defined(__SHA384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct sha384MacBlobContext Sha384MacBlobContext, * Sha384MacBlobContextPtr;

#endif

#if (defined(__SHA512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

typedef struct sha512MacBlobContext Sha512MacBlobContext, * Sha512MacBlobContextPtr;

#endif

#if (defined(__SHA3224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct sha3224MacBlobContext Sha3224MacBlobContext, * Sha3224MacBlobContextPtr;
#endif
#if (defined(__SHA3256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct sha3256MacBlobContext Sha3256MacBlobContext, * Sha3256MacBlobContextPtr;
#endif
#if (defined(__SHA3384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct sha3384MacBlobContext Sha3384MacBlobContext, * Sha3384MacBlobContextPtr;
#endif
#if (defined(__SHA3512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct sha3512MacBlobContext Sha3512MacBlobContext, * Sha3512MacBlobContextPtr;
#endif
#if (defined(__RIPEMD128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct ripeMD128MacBlobContext RipeMD128MacBlobContext, * RipeMD128MacBlobContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct ripeMD160MacBlobContext RipeMD160MacBlobContext, * RipeMD160MacBlobContextPtr;
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct ripeMD256MacBlobContext RipeMD256MacBlobContext, * RipeMD256MacBlobContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct ripeMD320MacBlobContext RipeMD320MacBlobContext, * RipeMD320MacBlobContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct blake2BMacBlobContext Blake2BMacBlobContext, * Blake2BMacBlobContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct blake2SMacBlobContext Blake2SMacBlobContext, * Blake2SMacBlobContextPtr;
#endif
#if (defined(__TIGER__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct tigerMacBlobContext TigerMacBlobContext, * TigerMacBlobContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct shake128MacBlobContext Shake128MacBlobContext, * Shake128MacBlobContextPtr;
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct shake256MacBlobContext Shake256MacBlobContext, * Shake256MacBlobContextPtr;
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct siphash64MacBlobContext Siphash64MacBlobContext, * Siphash64MacBlobContextPtr;
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct siphash128MacBlobContext Siphash128MacBlobContext, * Siphash128MacBlobContextPtr;
#endif
#if (defined(__LSH224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct lsh224MacBlobContext Lsh224MacBlobContext, * Lsh224MacBlobContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct lsh256MacBlobContext Lsh256MacBlobContext, * Lsh256MacBlobContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct lsh384MacBlobContext Lsh384MacBlobContext, * Lsh384MacBlobContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct lsh512MacBlobContext Lsh512MacBlobContext, * Lsh512MacBlobContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct sm3MacBlobContext Sm3MacBlobContext, * Sm3MacBlobContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )
typedef struct whirlpoolMacBlobContext WhirlpoolMacBlobContext, * WhirlpoolMacBlobContextPtr;
#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct cmacMacBlobContext CmacMacBlobContext, * CmacMacBlobContextPtr;
#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct cbccmacMacBlobContext CbcCmacMacBlobContext, * CbcCmacMacBlobContextPtr;
#endif

#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct dmacMacBlobContext DmacMacBlobContext, * DmacMacBlobContextPtr;
#endif

#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct gmacMacBlobContext GmacMacBlobContext, * GmacMacBlobContextPtr;
#endif

#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct hmacMacBlobContext HmacMacBlobContext, * HmacMacBlobContextPtr;
#endif

#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct poly1305MacBlobContext Poly1305MacBlobContext, * Poly1305MacBlobContextPtr;
#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct twotrackMacBlobContext TwoTrackMacBlobContext, * TwoTrackMacBlobContextPtr;
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct vmacMacBlobContext VmacMacBlobContext, * VmacMacBlobContextPtr;
#endif

#ifdef __cplusplus


#if (defined(__MD2__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Md2MacBlobContextPtr Md2MacInitialize(const char* key, unsigned int length);
extern "C" void Md2MacUpdate(Md2MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Md2MacFinalize(Md2MacBlobContextPtr macBlobContext);

#endif

#if (defined(__MD4__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Md4MacBlobContextPtr Md4MacInitialize(const char* key, unsigned int length);
extern "C" void Md4MacUpdate(Md4MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Md4MacFinalize(Md4MacBlobContextPtr macBlobContext);

#endif

#if (defined(__MD5__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Md5MacBlobContextPtr Md5MacInitialize(const char* key, unsigned int length);
extern "C" void Md5MacUpdate(Md5MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Md5MacFinalize(Md5MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA1__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha1MacBlobContextPtr Sha1MacInitialize(const char* key, unsigned int length);
extern "C" void Sha1MacUpdate(Sha1MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha1MacFinalize(Sha1MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha224MacBlobContextPtr Sha224MacInitialize(const char* key, unsigned int length);
extern "C" void Sha224MacUpdate(Sha224MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha224MacFinalize(Sha224MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha256MacBlobContextPtr Sha256MacInitialize(const char* key, unsigned int length);
extern "C" void Sha256MacUpdate(Sha256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha256MacFinalize(Sha256MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha384MacBlobContextPtr Sha384MacInitialize(const char* key, unsigned int length);
extern "C" void Sha384MacUpdate(Sha384MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha384MacFinalize(Sha384MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha512MacBlobContextPtr Sha512MacInitialize(const char* key, unsigned int length);
extern "C" void Sha512MacUpdate(Sha512MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha512MacFinalize(Sha512MacBlobContextPtr macBlobContext);

#endif


#if (defined(__SHA3224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha3224MacBlobContextPtr Sha3224MacInitialize(const char* key, unsigned int length);
extern "C" void Sha3224MacUpdate(Sha3224MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha3224MacFinalize(Sha3224MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA3256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha3256MacBlobContextPtr Sha3256MacInitialize(const char* key, unsigned int length);
extern "C" void Sha3256MacUpdate(Sha3256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha3256MacFinalize(Sha3256MacBlobContextPtr macBlobContext);

#endif
#if (defined(__SHA3384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha3384MacBlobContextPtr Sha3384MacInitialize(const char* key, unsigned int length);
extern "C" void Sha3384MacUpdate(Sha3384MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha3384MacFinalize(Sha3384MacBlobContextPtr macBlobContext);

#endif
#if (defined(__SHA3512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sha3512MacBlobContextPtr Sha3512MacInitialize(const char* key, unsigned int length);
extern "C" void Sha3512MacUpdate(Sha3512MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sha3512MacFinalize(Sha3512MacBlobContextPtr macBlobContext);

#endif


#if (defined(__RIPEMD128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" RipeMD128MacBlobContextPtr RipeMD128MacInitialize(const char* key, unsigned int length);
extern "C" void RipeMD128MacUpdate(RipeMD128MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD128MacFinalize(RipeMD128MacBlobContextPtr macBlobContext);

#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" RipeMD160MacBlobContextPtr RipeMD160MacInitialize(const char* key, unsigned int length);
extern "C" void RipeMD160MacUpdate(RipeMD160MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD160MacFinalize(RipeMD160MacBlobContextPtr macBlobContext);

#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" RipeMD256MacBlobContextPtr RipeMD256MacInitialize(const char* key, unsigned int length);
extern "C" void RipeMD256MacUpdate(RipeMD256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD256MacFinalize(RipeMD256MacBlobContextPtr macBlobContext);

#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" RipeMD320MacBlobContextPtr RipeMD320MacInitialize(const char* key, unsigned int length);
extern "C" void RipeMD320MacUpdate(RipeMD320MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* RipeMD320MacFinalize(RipeMD320MacBlobContextPtr macBlobContext);

#endif


#if (defined(__BLAKE2B__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Blake2BMacBlobContextPtr Blake2BMacInitialize(const char* key, unsigned int length);
extern "C" void Blake2BMacUpdate(Blake2BMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Blake2BMacFinalize(Blake2BMacBlobContextPtr macBlobContext);

#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Blake2SMacBlobContextPtr Blake2SMacInitialize(const char* key, unsigned int length);
extern "C" void Blake2SMacUpdate(Blake2SMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Blake2SMacFinalize(Blake2SMacBlobContextPtr macBlobContext);

#endif

#if (defined(__TIGER__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" TigerMacBlobContextPtr TigerMacInitialize(const char* key, unsigned int length);
extern "C" void TigerMacUpdate(TigerMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* TigerMacFinalize(TigerMacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Shake128MacBlobContextPtr Shake128MacInitialize(const char* key, unsigned int length);
extern "C" void Shake128MacUpdate(Shake128MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Shake128MacFinalize(Shake128MacBlobContextPtr macBlobContext);

#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Shake256MacBlobContextPtr Shake256MacInitialize(const char* key, unsigned int length);
extern "C" void Shake256MacUpdate(Shake256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Shake256MacFinalize(Shake256MacBlobContextPtr macBlobContext);

#endif


#if (defined(__SIPHASH64__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Siphash64MacBlobContextPtr Siphash64MacInitialize(const char* key, unsigned int length);
extern "C" void Siphash64MacUpdate(Siphash64MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Siphash64MacFinalize(Siphash64MacBlobContextPtr macBlobContext);

#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Siphash128MacBlobContextPtr Siphash128MacInitialize(const char* key, unsigned int length);
extern "C" void Siphash128MacUpdate(Siphash128MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Siphash128MacFinalize(Siphash128MacBlobContextPtr macBlobContext);

#endif

#if (defined(__LSH224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Lsh224MacBlobContextPtr Lsh224MacInitialize(const char* key, unsigned int length);
extern "C" void Lsh224MacUpdate(Lsh224MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Lsh224MacFinalize(Lsh224MacBlobContextPtr macBlobContext);

#endif
#if (defined(__LSH256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Lsh256MacBlobContextPtr Lsh256MacInitialize(const char* key, unsigned int length);
extern "C" void Lsh256MacUpdate(Lsh256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Lsh256MacFinalize(Lsh256MacBlobContextPtr macBlobContext);

#endif
#if (defined(__LSH384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Lsh384MacBlobContextPtr Lsh384MacInitialize(const char* key, unsigned int length);
extern "C" void Lsh384MacUpdate(Lsh384MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Lsh384MacFinalize(Lsh384MacBlobContextPtr macBlobContext);

#endif
#if (defined(__LSH512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Lsh512MacBlobContextPtr Lsh512MacInitialize(const char* key, unsigned int length);
extern "C" void Lsh512MacUpdate(Lsh512MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Lsh512MacFinalize(Lsh512MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SM3__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" Sm3MacBlobContextPtr Sm3MacInitialize(const char* key, unsigned int length);
extern "C" void Sm3MacUpdate(Sm3MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Sm3MacFinalize(Sm3MacBlobContextPtr macBlobContext);

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

extern "C" WhirlpoolMacBlobContextPtr WhirlpoolMacInitialize(const char* key, unsigned int length);
extern "C" void WhirlpoolMacUpdate(WhirlpoolMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* WhirlpoolMacFinalize(WhirlpoolMacBlobContextPtr macBlobContext);

#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" CmacMacBlobContextPtr CmacMacInitialize(const char* key, unsigned int length);
extern "C" void CmacMacUpdate(CmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* CmacMacFinalize(CmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" CbcCmacMacBlobContextPtr CbcCmacMacInitialize(const char* key, unsigned int length);
extern "C" void CbcCmacMacUpdate(CbcCmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* CbcCmacMacFinalize(CbcCmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" DmacMacBlobContextPtr DmacMacInitialize(const char* key, unsigned int length);
extern "C" void DmacMacUpdate(DmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* DmacMacFinalize(DmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" GmacMacBlobContextPtr GmacMacInitialize(const char* key, unsigned int length);
extern "C" void GmacMacUpdate(GmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* GmacMacFinalize(GmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" HmacMacBlobContextPtr HmacMacInitialize(const char* key, unsigned int length);
extern "C" void HmacMacUpdate(HmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* HmacMacFinalize(HmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" Poly1305MacBlobContextPtr Poly1305MacInitialize(const char* key, unsigned int length);
extern "C" void Poly1305MacUpdate(Poly1305MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* Poly1305MacFinalize(Poly1305MacBlobContextPtr macBlobContext);

#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" TwoTrackMacBlobContextPtr TwoTrackMacInitialize(const char* key, unsigned int length);
extern "C" void TwoTrackMacUpdate(TwoTrackMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* TwoTrackMacFinalize(TwoTrackMacBlobContextPtr macBlobContext);

#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

extern "C" VmacMacBlobContextPtr VmacMacInitialize(const char* key, unsigned int length);
extern "C" void VmacMacUpdate(VmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
extern "C" const char* VmacMacFinalize(VmacMacBlobContextPtr macBlobContext);

#endif



#else
#if (defined(__MD2__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Md2MacBlobContextPtr Md2MacInitialize(const char* key, unsigned int length);
void Md2MacUpdate(Md2MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Md2MacFinalize(Md2MacBlobContextPtr macBlobContext);

#endif

#if (defined(__MD4__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Md4MacBlobContextPtr Md4MacInitialize(const char* key, unsigned int length);
void Md4MacUpdate(Md4MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Md4MacFinalize(Md4MacBlobContextPtr macBlobContext);

#endif

#if (defined(__MD5__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Md5MacBlobContextPtr Md5MacInitialize(const char* key, unsigned int length);
void Md5MacUpdate(Md5MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Md5MacFinalize(Md5MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA1__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha1MacBlobContextPtr Sha1MacInitialize(const char* key, unsigned int length);
void Sha1MacUpdate(Sha1MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha1MacFinalize(Sha1MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha224MacBlobContextPtr Sha224MacInitialize(const char* key, unsigned int length);
void Sha224MacUpdate(Sha224MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha224MacFinalize(Sha224MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha256MacBlobContextPtr Sha256MacInitialize(const char* key, unsigned int length);
void Sha256MacUpdate(Sha256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha256MacFinalize(Sha256MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha384MacBlobContextPtr Sha384MacInitialize(const char* key, unsigned int length);
void Sha384MacUpdate(Sha384MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha384MacFinalize(Sha384MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha512MacBlobContextPtr Sha512MacInitialize(const char* key, unsigned int length);
void Sha512MacUpdate(Sha512MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha512MacFinalize(Sha512MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA3224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha3224MacBlobContextPtr Sha3224MacInitialize(const char* key, unsigned int length);
void Sha3224MacUpdate(Sha3224MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha3224MacFinalize(Sha3224MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA3256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha3256MacBlobContextPtr Sha3256MacInitialize(const char* key, unsigned int length);
void Sha3256MacUpdate(Sha3256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha3256MacFinalize(Sha3256MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA3384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha3384MacBlobContextPtr Sha3384MacInitialize(const char* key, unsigned int length);
void Sha3384MacUpdate(Sha3384MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha3384MacFinalize(Sha3384MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHA3512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sha3512MacBlobContextPtr Sha3512MacInitialize(const char* key, unsigned int length);
void Sha3512MacUpdate(Sha3512MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sha3512MacFinalize(Sha3512MacBlobContextPtr macBlobContext);

#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

RipeMD128MacBlobContextPtr RipeMD128MacInitialize(const char* key, unsigned int length);
void RipeMD128MacUpdate(RipeMD128MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* RipeMD128MacFinalize(RipeMD128MacBlobContextPtr macBlobContext);

#endif

#if (defined(__RIPEMD160__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

RipeMD160MacBlobContextPtr RipeMD160MacInitialize(const char* key, unsigned int length);
void RipeMD160MacUpdate(RipeMD160MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* RipeMD160MacFinalize(RipeMD160MacBlobContextPtr macBlobContext);

#endif

#if (defined(__RIPEMD256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

RipeMD256MacBlobContextPtr RipeMD256MacInitialize(const char* key, unsigned int length);
void RipeMD256MacUpdate(RipeMD256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* RipeMD256MacFinalize(RipeMD256MacBlobContextPtr macBlobContext);

#endif

#if (defined(__RIPEMD320__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

RipeMD320MacBlobContextPtr RipeMD320MacInitialize(const char* key, unsigned int length);
void RipeMD320MacUpdate(RipeMD320MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* RipeMD320MacFinalize(RipeMD320MacBlobContextPtr macBlobContext);

#endif

#if (defined(__BLAKE2B__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Blake2BMacBlobContextPtr Blake2BMacInitialize(const char* key, unsigned int length);
void Blake2BMacUpdate(Blake2BMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Blake2BMacFinalize(Blake2BMacBlobContextPtr macBlobContext);

#endif

#if (defined(__BLAKE2S__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Blake2SMacBlobContextPtr Blake2SMacInitialize(const char* key, unsigned int length);
void Blake2SMacUpdate(Blake2SMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Blake2SMacFinalize(Blake2SMacBlobContextPtr macBlobContext);

#endif

#if (defined(__TIGER__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

TigerMacBlobContextPtr TigerMacInitialize(const char* key, unsigned int length);
void TigerMacUpdate(TigerMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* TigerMacFinalize(TigerMacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Shake128MacBlobContextPtr Shake128MacInitialize(const char* key, unsigned int length);
void Shake128MacUpdate(Shake128MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Shake128MacFinalize(Shake128MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SHAKE256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Shake256MacBlobContextPtr Shake256MacInitialize(const char* key, unsigned int length);
void Shake256MacUpdate(Shake256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Shake256MacFinalize(Shake256MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SIPHASH64__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Siphash64MacBlobContextPtr Siphash64MacInitialize(const char* key, unsigned int length);
void Siphash64MacUpdate(Siphash64MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Siphash64MacFinalize(Siphash64MacBlobContextPtr macBlobContext);

#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Siphash128MacBlobContextPtr Siphash128MacInitialize(const char* key, unsigned int length);
void Siphash128MacUpdate(Siphash128MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Siphash128MacFinalize(Siphash128MacBlobContextPtr macBlobContext);

#endif

#if (defined(__LSH224__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Lsh224MacBlobContextPtr Lsh224MacInitialize(const char* key, unsigned int length);
void Lsh224MacUpdate(Lsh224MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Lsh224MacFinalize(Lsh224MacBlobContextPtr macBlobContext);

#endif

#if (defined(__LSH256__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Lsh256MacBlobContextPtr Lsh256MacInitialize(const char* key, unsigned int length);
void Lsh256MacUpdate(Lsh256MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Lsh256MacFinalize(Lsh256MacBlobContextPtr macBlobContext);

#endif
#if (defined(__LSH384__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Lsh384MacBlobContextPtr Lsh384MacInitialize(const char* key, unsigned int length);
void Lsh384MacUpdate(Lsh384MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Lsh384MacFinalize(Lsh384MacBlobContextPtr macBlobContext);

#endif
#if (defined(__LSH512__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Lsh512MacBlobContextPtr Lsh512MacInitialize(const char* key, unsigned int length);
void Lsh512MacUpdate(Lsh512MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Lsh512MacFinalize(Lsh512MacBlobContextPtr macBlobContext);

#endif

#if (defined(__SM3__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

Sm3MacBlobContextPtr Sm3MacInitialize(const char* key, unsigned int length);
void Sm3MacUpdate(Sm3MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Sm3MacFinalize(Sm3MacBlobContextPtr macBlobContext);

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) &&(  defined(__USE_BLOB__) && defined(__USE_MAC__) )

WhirlpoolMacBlobContextPtr WhirlpoolMacInitialize(const char* key, unsigned int length);
void WhirlpoolMacUpdate(WhirlpoolMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* WhirlpoolMacFinalize(WhirlpoolMacBlobContextPtr macBlobContext);

#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

CmacMacBlobContextPtr CmacMacInitialize(const char* key, unsigned int length);
void CmacMacUpdate(CmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* CmacMacFinalize(CmacMacBlobContextPtr macBlobContext);

#endif


#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

CbcCmacMacBlobContextPtr CbcCmacMacInitialize(const char* key, unsigned int length);
void CbcCmacMacUpdate(CbcCmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* CbcCmacMacFinalize(CbcCmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

DmacMacBlobContextPtr DmacMacInitialize(const char* key, unsigned int length);
void DmacMacUpdate(DmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* DmacMacFinalize(DmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

GmacMacBlobContextPtr GmacMacInitialize(const char* key, unsigned int length);
void GmacMacUpdate(GmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* GmacMacFinalize(GmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

HmacMacBlobContextPtr HmacMacInitialize(const char* key, unsigned int length);
void HmacMacUpdate(HmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* HmacMacFinalize(HmacMacBlobContextPtr macBlobContext);

#endif

#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

Poly1305MacBlobContextPtr Poly1305MacInitialize(const char* key, unsigned int length);
void Poly1305MacUpdate(Poly1305MacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* Poly1305MacFinalize(Poly1305MacBlobContextPtr macBlobContext);

#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

TwoTrackMacBlobContextPtr TwoTrackMacInitialize(const char* key, unsigned int length);
void TwoTrackMacUpdate(TwoTrackMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* TwoTrackMacFinalize(TwoTrackMacBlobContextPtr macBlobContext);

#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

VmacMacBlobContextPtr VmacMacInitialize(const char* key, unsigned int length);
void VmacMacUpdate(VmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length);
const char* VmacMacFinalize(VmacMacBlobContextPtr macBlobContext);

#endif




#endif