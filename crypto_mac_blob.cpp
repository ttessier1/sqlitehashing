
#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1


#include "crypto_mac_blob.h"

#include <cryptlib.h>
#include <filters.h>
#include <hmac.h>

#if defined(__MD2__) || defined (__ALL__)
#pragma message( "MD2 Set")
#include <md2.h>
#else 
#pragma message( "MD2 NOT Set")

#endif

#if defined(__MD4__) || defined (__ALL__)
#pragma message( "MD4 Set")
#include <md4.h>
#else
#pragma message( "MD4 NOT Set")
#endif

#if defined(__MD5__) || defined (__ALL__)
#pragma message( "MD5 Set")
#include <md5.h>
#else
#pragma message( "MD5 NOT Set")
#endif

#if defined(__SHA1__) ||defined(__SHA224__) ||defined(__SHA256__) || defined(__SHA384__) ||defined(__SHA512__) ||defined (__ALL__)
#pragma message( "SHA Set")
#if defined(__SHA1__) ||defined (__ALL__)
#pragma message( "SHA1 Set")
#else
#pragma message( "SHA1 NOT Set")
#endif
#if defined(__SHA224__) ||defined (__ALL__)
#pragma message( "SHA224 Set")
#else
#pragma message( "SHA224 NOT Set")
#endif
#if defined(__SHA256__) ||defined (__ALL__)
#pragma message( "SHA256 Set")
#else
#pragma message( "SHA265 NOT Set")
#endif
#if defined(__SHA384__) ||defined (__ALL__)
#pragma message( "SHA384 Set")
#else
#pragma message( "SHA384 NOT Set")
#endif
#if defined(__SHA512__) ||defined (__ALL__)
#pragma message( "SHA512 Set")
#else
#pragma message( "SHA512 NOT Set")
#endif
#include <sha.h>
#else
#pragma message( "SHA NOT Set")
#endif

#if defined(__SHA3224__) ||defined(__SHA3256__) ||defined(__SHA3384__) || defined(__SHA3512__) || (defined __ALL__)
#pragma message( "SHA3 Set")
#if defined(__SHA3224__) ||defined (__ALL__)
#pragma message( "SHA3224 Set")
#else
#pragma message( "SHA3224 NOT Set")
#endif
#if defined(__SHA3256__) ||defined (__ALL__)
#pragma message( "SHA3256 Set")
#else
#pragma message( "SHA3265 NOT Set")
#endif
#if defined(__SHA3384__) ||defined (__ALL__)
#pragma message( "SHA3384 Set")
#else
#pragma message( "SHA3384 NOT Set")
#endif
#if defined(__SHA3512__) ||defined (__ALL__)
#pragma message( "SHA3512 Set")
#else
#pragma message( "SHA3512 NOT Set")
#endif

#include <sha3.h>
#else
#pragma message( "SHA3 NOT Set")
#endif

#if defined(__RIPEMD128__) ||defined(__RIPEMD160__) ||defined(__RIPEMD256__) ||defined(__RIPEMD320__) || defined(__ALL__)
#if defined(__RIPEMD128__) ||defined (__ALL__)
#pragma message( "MD128 Set")
#else
#pragma message( "MD128 NOT Set")
#endif
#if defined(__RIPEMD160__) ||defined (__ALL__)
#pragma message( "MD160 Set")
#else
#pragma message( "MD160 NOT Set")
#endif
#if defined(__RIPEMD256__) ||defined (__ALL__)
#pragma message( "MD256 Set")
#else
#pragma message( "MD256 NOT Set")
#endif
#if defined(__RIPEMD320__) ||defined (__ALL__)
#pragma message( "MD320 Set")
#else
#pragma message( "MD256 NOT Set")
#endif
#include <ripemd.h>
#endif

#if defined(__BLAKE2B__) ||defined(__BLAKE2S__)|| defined(__ALL__)
#if defined(__BLAKE2B__) ||defined (__ALL__)
#pragma message( "BLAKE2B Set")
#else
#pragma message( "BLAKE2B NOT Set")
#endif
#if defined(__BLAKE2S__) ||defined (__ALL__)
#pragma message( "BLAKE2S Set")
#else
#pragma message( "BLAKE2S NOT Set")
#endif
#include <blake2.h>
#endif

#if defined(__TIGER__) || defined(__ALL__)
#pragma message( "TIGER Set")
#include <tiger.h>
#else
#pragma message( "TIGER NOT Set")
#endif

#if defined(__SHAKE128__)||defined(__SHAKE256__)|| defined(__ALL__)
#if defined(__SHAKE128__) ||defined (__ALL__)
#pragma message( "SHAKE128 Set")
#else
#pragma message( "SHAKE128 NOT Set")
#endif
#if defined(__SHAKE256__) ||defined (__ALL__)
#pragma message( "SHAKE256 Set")
#else
#pragma message( "SHAKE256 NOT Set")
#endif
#include <shake.h>
#endif

#if defined(__SIPHASH64__)||defined(__SIPHASH128__)|| defined(__ALL__)
#if defined(__SIPHASH64__) ||defined (__ALL__)
#pragma message( "SIPHASH64 Set")
#else
#pragma message( "SIPHASH64 NOT Set")
#endif
#if defined(__SIPHASH128__) ||defined (__ALL__)
#pragma message( "SIPHASH128 Set")
#else
#pragma message( "SIPHASH128 NOT Set")
#endif
#include <siphash.h>
#endif

#if defined(__LSH224__) ||defined(__LSH256__)||defined(__LSH384__)||defined(__LSH512__)|| defined(__ALL__)
#if defined(__LSH224__) ||defined (__ALL__)
#pragma message( "LSH224 Set")
#else
#pragma message( "LSH224 NOT Set")
#endif
#if defined(__LSH256__) ||defined (__ALL__)
#pragma message( "LSH256 Set")
#else
#pragma message( "LSH256 NOT Set")
#endif
#if defined(__LSH384__) ||defined (__ALL__)
#pragma message( "LSH384 Set")
#else
#pragma message( "LSH384 NOT Set")
#endif
#if defined(__LSH512__) ||defined (__ALL__)
#pragma message( "LSH512 Set")
#else
#pragma message( "LSH512 NOT Set")
#endif
#include <lsh.h>
#endif

#if defined(__SM3__) || defined(__ALL__)
#pragma message( "SM3 Set")
#include <sm3.h>
#else
#pragma message( "SM3 NOT Set")
#endif

#if defined(__WHIRLPOOL__) || defined(__ALL__)
#pragma message( "WHIRLPOOL Set")
#include <whrlpool.h>
#else
#pragma message( "WHIRLPOOL NOT Set")
#endif
#include <secblock.h>
#include <osrng.h>
#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <cmac.h>
#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <cbcmac.h>
#endif
#if (defined(__DMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <dmac.h>
#endif
#if (defined(__GMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <gcm.h>
#endif
#if (defined(__HMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <hmac.h>
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <poly1305.h>
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <ttmac.h>
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
#include <vmac.h>
#endif

#include <hex.h>
#include "algorithms.h"
#include "util.h"
#include "base64.h"
#include <factory.h>
#include <cstdarg>
#include <iostream>
#include <sstream>
#include <locale>
#include <cstdlib>
#include <ctime>

#ifdef CRYPTOPP_WIN32_AVAILABLE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#if defined(CRYPTOPP_UNIX_AVAILABLE) || defined(CRYPTOPP_BSD_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define UNIX_PATH_FAMILY 1
#endif

#if defined(CRYPTOPP_OSX_AVAILABLE)
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#define UNIX_PATH_FAMILY 1
#endif

#if (CRYPTOPP_MSC_VERSION >= 1000)
#include <crtdbg.h>		// for the debug heap
#endif

#if defined(__MWERKS__) && defined(macintosh)
#include <console.h>
#endif

#ifdef _OPENMP
# include <omp.h>
#endif

#ifdef __BORLANDC__
#pragma comment(lib, "cryptlib_bds.lib")
#endif

using namespace CryptoPP;
using namespace CryptoPP::Weak;
// Aggressive stack checking with VS2005 SP1 and above.
//#if (_MSC_FULL_VER >= 140050727)
//# pragma strict_gs_check (on)
//#endif

using namespace CryptoPP;
using namespace CryptoPP::Weak;

#if (defined(__MD2__) ||  defined(__MD4__) ||  defined(__MD5__) ||  defined (__ALL__)) && defined(__USE_BLOB__)



#if (defined(__MD2__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct md2MacBlobContext
{
    HMAC<MD2>* macBlobContext;
};
#endif

#if (defined(__MD4__) || defined(__ALL__))&& defined(__USE_BLOB__)
typedef struct md4MacBlobContext
{
    HMAC<MD4>* macBlobContext;
} Md4BlobMacBlobContext, * Md4BlobMacBlobContextPtr;
#endif

#if (defined(__MD5__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct md5MacBlobContext
{
    HMAC<MD5>* macBlobContext;
} Md5MacBlobContext, * Md5MacBlobContextPtr;
#endif

#endif


#if (defined(__SHA1__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha1MacBlobContext
{
    HMAC<SHA1>* macBlobContext;
} Sha1MacBlobContext, * Sha1MacBlobContextPtr;
#endif

#if (defined(__SHA224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha224MacBlobContext
{
    HMAC<SHA224>* macBlobContext;
} Sha224MacBlobContext, * Sha224MacBlobContextPtr;
#endif

#if (defined(__SHA256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha256MacBlobContext
{
    HMAC<SHA256>* macBlobContext;
} Sha256MacBlobContext, * Sha256MacBlobContextPtr;
#endif

#if (defined(__SHA384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha384MacBlobContext
{
    HMAC<SHA384>* macBlobContext;
} Sha384MacBlobContext, * Sha384MacBlobContextPtr;
#endif

#if (defined(__SHA512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha512MacBlobContext
{
    HMAC<SHA512>* macBlobContext;
} Sha512MacBlobContext, * Sha512MacBlobContextPtr;
#endif

#if (defined(__SHA3224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3224MacBlobContext
{
    HMAC<SHA3_224>* macBlobContext;
} Sha3224MacBlobContext, * Sha3224MacBlobContextPtr;
#endif

#if (defined(__SHA3256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3256MacBlobContext
{
    HMAC<SHA3_256>* macBlobContext;
} Sha3256MacBlobContext, * Sha3256MacBlobContextPtr;
#endif

#if (defined(__SHA3384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3384MacBlobContext
{
    HMAC<SHA3_384>* macBlobContext;
} Sha3384MacBlobContext, * Sha3384MacBlobContextPtr;
#endif

#if (defined(__SHA3512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3512MacBlobContext
{
    HMAC<SHA3_512>* macBlobContext;
} Sha3512MacBlobContext, * Sha3512MacBlobContextPtr;
#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD128MacBlobContext {
    HMAC<RIPEMD128>* macBlobContext;
}RipeMD128MacBlobContext, * RipeMD128MacBlobContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD160MacBlobContext {
    HMAC<RIPEMD160>* macBlobContext;
}RipeMD160MacBlobContext, * RipeMD160MacBlobContextPtr;
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD256MacBlobContext {
    HMAC<RIPEMD256>* macBlobContext;
}RipeMD256MacBlobContext, * RipeMD256MacBlobContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD320MacBlobContext {
    HMAC<RIPEMD320>* macBlobContext;
}RipeMD320MacBlobContext, * RipeMD320MacBlobContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2BMacBlobContext
{
    HMAC<BLAKE2b>* macBlobContext;
}Blake2BMacBlobContext, * Blake2BMacBlobContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2SMacBlobContext {
    HMAC<BLAKE2s>* macBlobContext;
}Blake2SMacBlobContext, * Blake2SMacBlobContextPtr;
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerMacBlobContext {
    HMAC<Tiger>* macBlobContext;
}TigerMacBlobContext, * TigerMacBlobContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake128MacBlobContext {
    HMAC<SHAKE128>* macBlobContext;
}Shake128MacBlobContext, * Shake128MacBlobContextPtr;
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake256MacBlobContext {
    HMAC<SHAKE256>* macBlobContext;
}Shake256MacBlobContext, * Shake256MacBlobContextPtr;
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash64MacBlobContext {
    SipHash<2, 4, false>* macBlobContext;
}Siphash64MacBlobContext, * Siphash64MacBlobContextPtr;
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash128MacBlobContext {
    SipHash<4, 8, true>* macBlobContext;
}Siphash128MacBlobContext, * Siphash128MacBlobContextPtr;
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh224MacBlobContext {
    HMAC<LSH224>* macBlobContext;
}Lsh224MacBlobContext, * Lsh224MacBlobContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh256MacBlobContext {
    HMAC<LSH256>* macBlobContext;
}Lsh256MacBlobContext, * Lsh256MacBlobContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh384MacBlobContext {
    HMAC<LSH384>* macBlobContext;
}Lsh384MacBlobContext, * Lsh384MacBlobContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh512MacBlobContext {
    HMAC<LSH512>* macBlobContext;
} Lsh512MacBlobContext, * Lsh512MacBlobContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sm3MacBlobContext {
    HMAC<SM3>* macBlobContext;
}Sm3MacBlobContext, * Sm3MacBlobContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct whirlpoolMacBlobContext {
    HMAC<Whirlpool>* macBlobContext;
}WhirlpoolMacBlobContext, * WhirlpoolMacBlobContextPtr;
#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct cmacMacBlobContext
{
    CMAC<AES> * macBlobContext;
}CmacMacBlobContext, * CmacMacBlobContextPtr;
#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct cbccmacMacBlobContext
{
    CBC_MAC<AES> * macBlobContext;
}CbcCmacMacBlobContext, * CbcCmacMacBlobContextPtr;
#endif

#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct dmacMacBlobContext {
    DMAC<AES>* macBlobContext;
}DmacMacBlobContext, * DmacMacBlobContextPtr;
#endif

#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct gmacMacBlobContext {
    GCM<AES>::Encryption * macBlobContext;
}GmacMacBlobContext, * GmacMacBlobContextPtr;
#endif

#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct hmacMacBlobContext {
    HMAC<SHA256> * macBlobContext;
}HmacMacBlobContext, * HmacMacBlobContextPtr;
#endif

#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct poly1305MacBlobContext {
    Poly1305<AES>* macBlobContext;
}Poly1305MacBlobContext, * Poly1305MacBlobContextPtr;
#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct twotrackMacBlobContext
{
    TTMAC * macBlobContext;
}TwoTrackMacBlobContext, * TwoTrackMacBlobContextPtr;
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
typedef struct vmacMacBlobContext
{
    VMAC<AES> * macBlobContext;
}VmacMacBlobContext, * VmacMacBlobContextPtr;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__MD2__) || defined (__ALL__)) && (defined(__USE_BLOB__)&& defined(__USE_MAC__))
    Md2MacBlobContextPtr Md2MacInitialize(const char* key, unsigned int length)
    {
        Md2MacBlobContextPtr macbBobContext = NULL;
        if (key != NULL && length > 0 )
        {
            macbBobContext = (Md2MacBlobContextPtr)malloc(sizeof(Md2MacBlobContext));
            if (macbBobContext != NULL)
            {
                new(macbBobContext)Md2MacBlobContextPtr();
                macbBobContext->macBlobContext = (HMAC<MD2>*)malloc(sizeof(HMAC<MD2>));
                if (macbBobContext->macBlobContext)
                {
                    new(macbBobContext->macBlobContext) HMAC<MD2>((CryptoPP::byte*)key,length);
                }
                else
                {
                    free(macbBobContext);
                    macbBobContext = NULL;
                }
            }
        }
        return macbBobContext;
    }

    void Md2MacUpdate(Md2MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext!= NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md2MacFinalize(Md2MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(MD2::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, MD2::DIGESTSIZE, algo_md2);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (MD2::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (MD2::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__MD4__) || defined(__ALL__))&& defined(__USE_BLOB__)

    Md4MacBlobContextPtr Md4MacInitialize(const char* key, unsigned int length)
    {
        Md4MacBlobContextPtr macbBobContext = NULL;
        if (key != NULL && length > 0)
        {
            macbBobContext = (Md4MacBlobContextPtr)malloc(sizeof(Md4MacBlobContext));
            if (macbBobContext != NULL)
            {
                new(macbBobContext)Md4MacBlobContextPtr();
                macbBobContext->macBlobContext = (HMAC<MD4>*)malloc(sizeof(HMAC<MD4>));
                if (macbBobContext->macBlobContext)
                {
                    new(macbBobContext->macBlobContext) HMAC<MD4>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macbBobContext);
                    macbBobContext = NULL;
                }
            }
        }
        return macbBobContext;
    }

    void Md4MacUpdate(Md4MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md4MacFinalize(Md4MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(MD4::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, MD4::DIGESTSIZE, algo_md4);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (MD4::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (MD4::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__MD5__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Md5MacBlobContextPtr Md5MacInitialize(const char* key, unsigned int length)
    {
        Md5MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Md5MacBlobContextPtr)malloc(sizeof(Md5MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Md5MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<MD5>*)malloc(sizeof(HMAC<MD5>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<MD5>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Md5MacUpdate(Md5MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md5MacFinalize(Md5MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(MD5::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, MD5::DIGESTSIZE, algo_md5);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (MD5::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (MD5::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA1__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha1MacBlobContextPtr Sha1MacInitialize(const char* key, unsigned int length)
    {
        Sha1MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha1MacBlobContextPtr)malloc(sizeof(Sha1MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha1MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA1>*)malloc(sizeof(HMAC<SHA1>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA1>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha1MacUpdate(Sha1MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha1MacFinalize(Sha1MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA1::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA1::DIGESTSIZE, algo_sha1);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA1::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA1::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA224__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha224MacBlobContextPtr Sha224MacInitialize(const char* key, unsigned int length)
    {
        Sha224MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha224MacBlobContextPtr)malloc(sizeof(Sha224MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha224MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA224>*)malloc(sizeof(HMAC<SHA224>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA224>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha224MacUpdate(Sha224MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha224MacFinalize(Sha224MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA224::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA224::DIGESTSIZE, algo_sha224);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA224::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA224::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA256__)||defined(__ALL__)) && defined(__USE_BLOB__)

    Sha256MacBlobContextPtr Sha256MacInitialize(const char* key, unsigned int length)
    {
        Sha256MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha256MacBlobContextPtr)malloc(sizeof(Sha256MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha256MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA256>*)malloc(sizeof(HMAC<SHA256>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA256>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha256MacUpdate(Sha256MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha256MacFinalize(Sha256MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA256::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA256::DIGESTSIZE, algo_sha256);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA256::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA256::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA384__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha384MacBlobContextPtr Sha384MacInitialize(const char* key, unsigned int length)
    {
        Sha384MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha384MacBlobContextPtr)malloc(sizeof(Sha384MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha384MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA384>*)malloc(sizeof(HMAC<SHA384>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA384>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha384MacUpdate(Sha384MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha384MacFinalize(Sha384MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA384::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA384::DIGESTSIZE, algo_sha384);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA384::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA384::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA512__)||defined(__ALL__)) && defined(__USE_BLOB__)

    Sha512MacBlobContextPtr Sha512MacInitialize(const char* key, unsigned int length)
    {
        Sha512MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha512MacBlobContextPtr)malloc(sizeof(Sha512MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha512MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA512>*)malloc(sizeof(HMAC<SHA512>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA512>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha512MacUpdate(Sha512MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha512MacFinalize(Sha512MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA512::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA512::DIGESTSIZE, algo_sha512);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA512::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA512::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA3224__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3224MacBlobContextPtr Sha3224MacInitialize(const char* key, unsigned int length)
    {
        Sha3224MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha3224MacBlobContextPtr)malloc(sizeof(Sha3224MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha3224MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA3_224>*)malloc(sizeof(HMAC<SHA3_224>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA3_224>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha3224MacUpdate(Sha3224MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3224MacFinalize(Sha3224MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_224::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA3_224::DIGESTSIZE, algo_sha3_224);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA3_224::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA3_224::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA3256__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3256MacBlobContextPtr Sha3256MacInitialize(const char* key, unsigned int length)
    {
        Sha3256MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha3256MacBlobContextPtr)malloc(sizeof(Sha3256MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha3256MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA3_256>*)malloc(sizeof(HMAC<SHA3_256>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA3_256>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha3256MacUpdate(Sha3256MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3256MacFinalize(Sha3256MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_256::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA3_256::DIGESTSIZE, algo_sha3_256);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA3_256::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA3_256::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA3384__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3384MacBlobContextPtr Sha3384MacInitialize(const char* key, unsigned int length)
    {
        Sha3384MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha3384MacBlobContextPtr)malloc(sizeof(Sha3384MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha3384MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA3_384>*)malloc(sizeof(HMAC<SHA3_384>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA3_384>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha3384MacUpdate(Sha3384MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3384MacFinalize(Sha3384MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_384::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA3_384::DIGESTSIZE, algo_sha3_384);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA3_384::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA3_384::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA3512__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3512MacBlobContextPtr Sha3512MacInitialize(const char* key, unsigned int length)
    {
        Sha3512MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sha3512MacBlobContextPtr)malloc(sizeof(Sha3512MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sha3512MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA3_512>*)malloc(sizeof(HMAC<SHA3_512>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA3_512>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sha3512MacUpdate(Sha3512MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3512MacFinalize(Sha3512MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_512::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHA3_512::DIGESTSIZE, algo_sha3_512);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHA3_512::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHA3_512::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD128MacBlobContextPtr RipeMD128MacInitialize(const char* key, unsigned int length)
    {
        RipeMD128MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (RipeMD128MacBlobContextPtr)malloc(sizeof(RipeMD128MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)RipeMD128MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<RIPEMD128>*)malloc(sizeof(HMAC<RIPEMD128>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<RIPEMD128>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void RipeMD128MacUpdate(RipeMD128MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD128MacFinalize(RipeMD128MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD128::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, RIPEMD128::DIGESTSIZE, algo_ripemd_128);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (RIPEMD128::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (RIPEMD128::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD160MacBlobContextPtr RipeMD160MacInitialize(const char* key, unsigned int length)
    {
        RipeMD160MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (RipeMD160MacBlobContextPtr)malloc(sizeof(RipeMD160MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)RipeMD160MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<RIPEMD160>*)malloc(sizeof(HMAC<RIPEMD160>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<RIPEMD160>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void RipeMD160MacUpdate(RipeMD160MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD160MacFinalize(RipeMD160MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD160::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, RIPEMD160::DIGESTSIZE, algo_ripemd_160);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (RIPEMD160::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (RIPEMD160::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD256MacBlobContextPtr RipeMD256MacInitialize(const char* key, unsigned int length)
    {
        RipeMD256MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (RipeMD256MacBlobContextPtr)malloc(sizeof(RipeMD256MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)RipeMD256MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<RIPEMD256>*)malloc(sizeof(HMAC<RIPEMD256>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<RIPEMD256>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void RipeMD256MacUpdate(RipeMD256MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD256MacFinalize(RipeMD256MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD256::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, RIPEMD256::DIGESTSIZE, algo_ripemd_256);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (RIPEMD256::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (RIPEMD256::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD320MacBlobContextPtr RipeMD320MacInitialize(const char* key, unsigned int length)
    {
        RipeMD320MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (RipeMD320MacBlobContextPtr)malloc(sizeof(RipeMD320MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)RipeMD320MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<RIPEMD320>*)malloc(sizeof(HMAC<RIPEMD320>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<RIPEMD320>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void RipeMD320MacUpdate(RipeMD320MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD320MacFinalize(RipeMD320MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD320::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, RIPEMD320::DIGESTSIZE, algo_ripemd_320);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (RIPEMD320::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (RIPEMD320::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Blake2BMacBlobContextPtr Blake2BMacInitialize(const char* key, unsigned int length)
    {
        Blake2BMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Blake2BMacBlobContextPtr)malloc(sizeof(Blake2BMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Blake2BMacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<BLAKE2b>*)malloc(sizeof(HMAC<BLAKE2b>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<BLAKE2b>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Blake2BMacUpdate(Blake2BMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Blake2BMacFinalize(Blake2BMacBlobContextPtr macBlobContext)
    {

        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(BLAKE2b::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, BLAKE2b::DIGESTSIZE, algo_blake2b);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (BLAKE2b::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (BLAKE2b::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Blake2SMacBlobContextPtr Blake2SMacInitialize(const char* key, unsigned int length)
    {
        Blake2SMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Blake2SMacBlobContextPtr)malloc(sizeof(Blake2SMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Blake2SMacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<BLAKE2s>*)malloc(sizeof(HMAC<BLAKE2s>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<BLAKE2s>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Blake2SMacUpdate(Blake2SMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Blake2SMacFinalize(Blake2SMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(BLAKE2s::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, BLAKE2s::DIGESTSIZE, algo_blake2s);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (BLAKE2s::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (BLAKE2s::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
    TigerMacBlobContextPtr TigerMacInitialize(const char* key, unsigned int length)
    {
        TigerMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (TigerMacBlobContextPtr)malloc(sizeof(TigerMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)TigerMacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<Tiger>*)malloc(sizeof(HMAC<Tiger>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<Tiger>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void TigerMacUpdate(TigerMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* TigerMacFinalize(TigerMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(Tiger::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, Tiger::DIGESTSIZE, algo_tiger);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (Tiger::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (Tiger::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Shake128MacBlobContextPtr Shake128MacInitialize(const char* key, unsigned int length)
    {
        Shake128MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Shake128MacBlobContextPtr)malloc(sizeof(Shake128MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Shake128MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHAKE128>*)malloc(sizeof(HMAC<SHAKE128>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHAKE128>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Shake128MacUpdate(Shake128MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Shake128MacFinalize(Shake128MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHAKE128::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHAKE128::DIGESTSIZE, algo_shake_128);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHAKE128::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHAKE128::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Shake256MacBlobContextPtr Shake256MacInitialize(const char* key, unsigned int length)
    {
        Shake256MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Shake256MacBlobContextPtr)malloc(sizeof(Shake256MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Shake256MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHAKE256>*)malloc(sizeof(HMAC<SHAKE256>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHAKE256>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Shake256MacUpdate(Shake256MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Shake256MacFinalize(Shake256MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHAKE256::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SHAKE256::DIGESTSIZE, algo_shake_256);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SHAKE256::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SHAKE256::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Siphash64MacBlobContextPtr Siphash64MacInitialize(const char* key, unsigned int length)
    {
        Siphash64MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Siphash64MacBlobContextPtr)malloc(sizeof(Siphash64MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Siphash64MacBlobContextPtr();
                macBlobContext->macBlobContext = (SipHash<2,4,false>*)malloc(sizeof(SipHash<2, 4, false>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) SipHash<2, 4, false>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Siphash64MacUpdate(Siphash64MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            //macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Siphash64MacFinalize(Siphash64MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SipHash<2,4,false>::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SipHash<2, 4, false>::DIGESTSIZE, algo_sip_hash64);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SipHash<2, 4, false>::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SipHash<2, 4, false>::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Siphash128MacBlobContextPtr Siphash128MacInitialize(const char* key, unsigned int length)
    {
        Siphash128MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Siphash128MacBlobContextPtr)malloc(sizeof(Siphash128MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Siphash128MacBlobContextPtr();
                macBlobContext->macBlobContext = (SipHash<4, 8, true>*)malloc(sizeof(SipHash<4, 8, true>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) SipHash<4, 8, true>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Siphash128MacUpdate(Siphash128MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            //macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Siphash128MacFinalize(Siphash128MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SipHash<4, 8, true>::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SipHash<4, 8, true>::DIGESTSIZE, algo_sip_hash128);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SipHash<4, 8, true>::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SipHash<4, 8, true>::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh224MacBlobContextPtr Lsh224MacInitialize(const char* key, unsigned int length)
    {
        Lsh224MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Lsh224MacBlobContextPtr)malloc(sizeof(Lsh224MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Lsh224MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<LSH224>*)malloc(sizeof(HMAC<LSH224>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<LSH224>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Lsh224MacUpdate(Lsh224MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh224MacFinalize(Lsh224MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH224::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, LSH224::DIGESTSIZE, algo_lsh_224);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (LSH224::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (LSH224::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh256MacBlobContextPtr Lsh256MacInitialize(const char* key, unsigned int length)
    {
        Lsh256MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Lsh256MacBlobContextPtr)malloc(sizeof(Lsh256MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Lsh256MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<LSH256>*)malloc(sizeof(HMAC<LSH256>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<LSH256>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Lsh256MacUpdate(Lsh256MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh256MacFinalize(Lsh256MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH256::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, LSH256::DIGESTSIZE, algo_lsh_256);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (LSH256::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (LSH256::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh384MacBlobContextPtr Lsh384MacInitialize(const char* key, unsigned int length)
    {
        Lsh384MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Lsh384MacBlobContextPtr)malloc(sizeof(Lsh384MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Lsh384MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<LSH384>*)malloc(sizeof(HMAC<LSH384>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<LSH384>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Lsh384MacUpdate(Lsh384MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh384MacFinalize(Lsh384MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH384::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, LSH384::DIGESTSIZE, algo_lsh_384);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (LSH384::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (LSH384::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh512MacBlobContextPtr Lsh512MacInitialize(const char* key, unsigned int length)
    {
        Lsh512MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Lsh512MacBlobContextPtr)malloc(sizeof(Lsh512MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Lsh512MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<LSH512>*)malloc(sizeof(HMAC<LSH512>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<LSH512>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Lsh512MacUpdate(Lsh512MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh512MacFinalize(Lsh512MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH512::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, LSH512::DIGESTSIZE, algo_lsh_512);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (LSH512::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (LSH512::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Sm3MacBlobContextPtr Sm3MacInitialize(const char* key, unsigned int length)
    {
        Sm3MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Sm3MacBlobContextPtr)malloc(sizeof(Sm3MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Sm3MacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SM3>*)malloc(sizeof(HMAC<SM3>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SM3>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void Sm3MacUpdate(Sm3MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sm3MacFinalize(Sm3MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(SM3::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, SM3::DIGESTSIZE, algo_sm3);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (SM3::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (SM3::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
    WhirlpoolMacBlobContextPtr WhirlpoolMacInitialize(const char* key, unsigned int length)
    {
        WhirlpoolMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (WhirlpoolMacBlobContextPtr)malloc(sizeof(WhirlpoolMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)WhirlpoolMacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<Whirlpool>*)malloc(sizeof(HMAC<Whirlpool>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<Whirlpool>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void WhirlpoolMacUpdate(WhirlpoolMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* WhirlpoolMacFinalize(WhirlpoolMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(Whirlpool::DIGESTSIZE);
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, Whirlpool::DIGESTSIZE, algo_whirlpool);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (Whirlpool::DIGESTSIZE * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (Whirlpool::DIGESTSIZE * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }
#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    CmacMacBlobContextPtr CmacMacInitialize(const char* key, unsigned int length)
    {
        CmacMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (CmacMacBlobContextPtr)malloc(sizeof(CmacMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)CmacMacBlobContextPtr();
                macBlobContext->macBlobContext = (CMAC<AES>*)malloc(sizeof(CMAC<AES>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) CMAC<AES>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }
    void CmacMacUpdate(CmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }
    const char* CmacMacFinalize(CmacMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_cmac);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    CbcCmacMacBlobContextPtr CbcCmacMacInitialize(const char* key, unsigned int length)
    {
        CbcCmacMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (CbcCmacMacBlobContextPtr)malloc(sizeof(CbcCmacMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)CbcCmacMacBlobContextPtr();
                macBlobContext->macBlobContext = (CBC_MAC<AES>*)malloc(sizeof(CBC_MAC<AES>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) CBC_MAC<AES>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void CbcCmacMacUpdate(CbcCmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* CbcCmacMacFinalize(CbcCmacMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_cbc_mac);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    DmacMacBlobContextPtr DmacMacInitialize(const char* key, unsigned int length)
    {
        DmacMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (DmacMacBlobContextPtr)malloc(sizeof(DmacMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)DmacMacBlobContextPtr();
                macBlobContext->macBlobContext = (DMAC<AES>*)malloc(sizeof(DMAC<AES>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) DMAC<AES>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }
    void DmacMacUpdate(DmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }
    const char* DmacMacFinalize(DmacMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_dmac);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    GmacMacBlobContextPtr GmacMacInitialize(const char* key, unsigned int length)
    {
        GmacMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (GmacMacBlobContextPtr)malloc(sizeof(GmacMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)GmacMacBlobContextPtr();
                macBlobContext->macBlobContext = (GCM<AES>::Encryption*)malloc(sizeof(GCM<AES>::Encryption));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) GCM<AES>::Encryption();
                    SecByteBlock iv(AES::BLOCKSIZE);
                    memset(iv, 0x00, iv.size());
                    macBlobContext->macBlobContext->SetKeyWithIV((CryptoPP::byte*)key, length, iv, iv.size());
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }
    void GmacMacUpdate(GmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }
    const char* GmacMacFinalize(GmacMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_gmac);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    HmacMacBlobContextPtr HmacMacInitialize(const char* key, unsigned int length)
    {
        HmacMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (HmacMacBlobContextPtr)malloc(sizeof(HmacMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)HmacMacBlobContextPtr();
                macBlobContext->macBlobContext = (HMAC<SHA256>*)malloc(sizeof(HMAC<SHA256>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) HMAC<SHA256>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }

    void HmacMacUpdate(HmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* HmacMacFinalize(HmacMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_hmac);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    Poly1305MacBlobContextPtr Poly1305MacInitialize(const char* key, unsigned int length)
    {
        Poly1305MacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (Poly1305MacBlobContextPtr)malloc(sizeof(Poly1305MacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)Poly1305MacBlobContextPtr();
                macBlobContext->macBlobContext = (Poly1305<AES>*)malloc(sizeof(Poly1305<AES>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) Poly1305<AES>((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }
    void Poly1305MacUpdate(Poly1305MacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }
    const char* Poly1305MacFinalize(Poly1305MacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_poly_1305);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    TwoTrackMacBlobContextPtr TwoTrackMacInitialize(const char* key, unsigned int length)
    {
        TwoTrackMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (TwoTrackMacBlobContextPtr)malloc(sizeof(TwoTrackMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)TwoTrackMacBlobContextPtr();
                macBlobContext->macBlobContext = (TTMAC*)malloc(sizeof(TTMAC));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) TTMAC((CryptoPP::byte*)key, length);
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }
    void TwoTrackMacUpdate(TwoTrackMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }
    const char* TwoTrackMacFinalize(TwoTrackMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_two_track);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif

#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

    VmacMacBlobContextPtr VmacMacInitialize(const char* key, unsigned int length)
    {
        VmacMacBlobContextPtr macBlobContext = NULL;
        if (key != NULL && length > 0)
        {
            macBlobContext = (VmacMacBlobContextPtr)malloc(sizeof(VmacMacBlobContext));
            if (macBlobContext != NULL)
            {
                new(macBlobContext)VmacMacBlobContextPtr();
                macBlobContext->macBlobContext = (VMAC<AES>*)malloc(sizeof(VMAC<AES>));
                if (macBlobContext->macBlobContext)
                {
                    new(macBlobContext->macBlobContext) VMAC<AES>();
                    SecByteBlock iv(AES::BLOCKSIZE);
                    memset(iv, 0x00, iv.size());
                    macBlobContext->macBlobContext->SetKeyWithIV((CryptoPP::byte*)key, length, iv, iv.size());
                }
                else
                {
                    free(macBlobContext);
                    macBlobContext = NULL;
                }
            }
        }
        return macBlobContext;
    }
    void VmacMacUpdate(VmacMacBlobContextPtr macBlobContext, const char* message, unsigned int length)
    {
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL && message != NULL)
        {
            macBlobContext->macBlobContext->Update((CryptoPP::byte*)message, length);
        }
    }
    const char* VmacMacFinalize(VmacMacBlobContextPtr macBlobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (macBlobContext != NULL && macBlobContext->macBlobContext != NULL)
        {
            lpBuffer = (char*)malloc(macBlobContext->macBlobContext->DigestSize());
            if (lpBuffer)
            {
                macBlobContext->macBlobContext->Final((CryptoPP::byte*)lpBuffer);
                result = ToHex(lpBuffer, macBlobContext->macBlobContext->DigestSize(), algo_vmac);
                if (result != NULL)
                {
                    DebugMessage("Processed ToHex\r\n");
                    if (strlen(result) != (macBlobContext->macBlobContext->DigestSize() * 2))
                    {
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlength(result), (macBlobContext->macBlobContext->DigestSize() * 2), result);
                        return NULL;
                    }
                }
                else
                {
                    DebugMessage("Failed to convert to hex\r\n");
                }
                free(lpBuffer);
                lpBuffer = NULL;
                return result;
            }
            else
            {
                DebugMessage("Failed to allocate memory to hex\r\n");
            }
        }
        else
        {
            DebugMessage("Invalid BlobContext\r\n");
        }
        return result;
    }

#endif


#ifdef __cplusplus
}
#endif