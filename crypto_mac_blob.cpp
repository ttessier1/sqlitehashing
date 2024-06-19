
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
    CryptoPP::Weak1::MD5* macBlobContext;
} Md5MacBlobContext, * Md5MacBlobContextPtr;
#endif

#endif


#if (defined(__SHA1__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha1MacBlobContext
{
    SHA1* macBlobContext;
} Sha1MacBlobContext, * Sha1MacBlobContextPtr;
#endif

#if (defined(__SHA224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha224MacBlobContext
{
    SHA224* macBlobContext;
} Sha224MacBlobContext, * Sha224MacBlobContextPtr;
#endif

#if (defined(__SHA256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha256MacBlobContext
{
    SHA256* macBlobContext;
} Sha256MacBlobContext, * Sha256MacBlobContextPtr;
#endif

#if (defined(__SHA384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha384MacBlobContext
{
    SHA384* macBlobContext;
} Sha384MacBlobContext, * Sha384MacBlobContextPtr;
#endif

#if (defined(__SHA512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha512MacBlobContext
{
    SHA512* macBlobContext;
} Sha512MacBlobContext, * Sha512MacBlobContextPtr;
#endif

#if (defined(__SHA3224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3224MacBlobContext
{
    SHA3_224* macBlobContext;
} Sha3224MacBlobContext, * Sha3224MacBlobContextPtr;
#endif

#if (defined(__SHA3256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3256MacBlobContext
{
    SHA3_256* macBlobContext;
} Sha3256MacBlobContext, * Sha3256MacBlobContextPtr;
#endif

#if (defined(__SHA3384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3384MacBlobContext
{
    SHA3_384* macBlobContext;
} Sha3384MacBlobContext, * Sha3384MacBlobContextPtr;
#endif

#if (defined(__SHA3512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3512MacBlobContext
{
    SHA3_512* macBlobContext;
} Sha3512MacBlobContext, * Sha3512MacBlobContextPtr;
#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD128MacBlobContext {
    RIPEMD128* macBlobContext;
}RipeMD128MacBlobContext, * RipeMD128MacBlobContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD160MacBlobContext {
    RIPEMD160* macBlobContext;
}RipeMD160MacBlobContext, * RipeMD160MacBlobContextPtr;
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD256MacBlobContext {
    RIPEMD256* macBlobContext;
}RipeMD256MacBlobContext, * RipeMD256MacBlobContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD320MacBlobContext {
    RIPEMD320* macBlobContext;
}RipeMD320MacBlobContext, * RipeMD320MacBlobContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2BMacBlobContext
{
    BLAKE2b* macBlobContext;
}Blake2BMacBlobContext, * Blake2BMacBlobContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2SMacBlobContext {
    BLAKE2s* macBlobContext;
}Blake2SMacBlobContext, * Blake2SMacBlobContextPtr;
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerMacBlobContext {
    Tiger* macBlobContext;
}TigerMacBlobContext, * TigerMacBlobContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake128MacBlobContext {
    SHAKE128* macBlobContext;
}Shake128MacBlobContext, * Shake128MacBlobContextPtr;
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake256MacBlobContext {
    SHAKE256* macBlobContext;
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
    LSH224* macBlobContext;
}Lsh224MacBlobContext, * Lsh224MacBlobContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh256MacBlobContext {
    LSH256* macBlobContext;
}Lsh256MacBlobContext, * Lsh256MacBlobContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh384MacBlobContext {
    LSH384* macBlobContext;
}Lsh384MacBlobContext, * Lsh384MacBlobContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh512MacBlobContext {
    LSH512* macBlobContext;
} Lsh512MacBlobContext, * Lsh512MacBlobContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sm3MacBlobContext {
    SM3* macBlobContext;
}Sm3MacBlobContext, * Sm3MacBlobContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct whirlpoolMacBlobContext {
    Whirlpool* macBlobContext;
}WhirlpoolMacBlobContext, * WhirlpoolMacBlobContextPtr;
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
                macbBobContext->macBlobContext = (HMAC<MD2>*)malloc(sizeof(MD2));
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
                macbBobContext->macBlobContext = (HMAC<MD4>*)malloc(sizeof(MD2));
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
    Md5MacBlobContextPtr Md5MacInitialize()
    {
        return NULL;
    }

    void Md5UMacpdate(Md5MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Md5MacFinalize(Md5MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif

#if (defined(__SHA1__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha1MacBlobContextPtr Sha1MacInitialize()
    {
        return NULL;
    }

    void Sha1UMacpdate(Sha1MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha1MacFinalize(Sha1MacBlobContextPtr blobContext)
    {
        return NULL;
    }

#endif

#if (defined(__SHA224__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha224MacBlobContextPtr Sha224MacInitialize()
    {
        return NULL;
    }

    void Sha224UMacpdate(Sha224MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha224MacFinalize(Sha224MacBlobContextPtr blobContext)
    {
        return NULL;
    }

#endif

#if (defined(__SHA256__)||defined(__ALL__)) && defined(__USE_BLOB__)

    Sha256MacBlobContextPtr Sha256MacInitialize()
    {
        return NULL;
    }

    void Sha256UMacpdate(Sha256MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha256MacFinalize(Sha256MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif

#if (defined(__SHA384__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha384MacBlobContextPtr Sha384MacInitialize()
    {
        return NULL;
    }

    void Sha384UMacpdate(Sha384MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha384MacFinalize(Sha384MacBlobContextPtr blobContext)
    {
        return NULL;
    }

#endif

#if (defined(__SHA512__)||defined(__ALL__)) && defined(__USE_BLOB__)

    Sha512MacBlobContextPtr Sha512MacInitialize()
    {
        return NULL;
    }

    void Sha512UMacpdate(Sha512MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha512MacFinalize(Sha512MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif

#if (defined(__SHA3224__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3224MacBlobContextPtr Sha3224MacInitialize()
    {
        return NULL;
    }

    void Sha3224UMacpdate(Sha3224MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha3224MacFinalize(Sha3224MacBlobContextPtr blobContext)
    {
        return NULL;
    }

#endif

#if (defined(__SHA3256__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3256MacBlobContextPtr Sha3256MacInitialize()
    {
        return NULL;
    }

    void Sha3256UMacpdate(Sha3256MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha3256MacFinalize(Sha3256MacBlobContextPtr blobContext)
    {
        return NULL;
    }

#endif

#if (defined(__SHA3384__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3384MacBlobContextPtr Sha3384MacInitialize()
    {
        return NULL;
    }

    void Sha3384UMacpdate(Sha3384MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha3384MacFinalize(Sha3384MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif

#if (defined(__SHA3512__)||defined(__ALL__)) && defined(__USE_BLOB__)
    Sha3512MacBlobContextPtr Sha3512MacInitialize()
    {
        return NULL;
    }

    void Sha3512UMacpdate(Sha3512MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sha3512MacFinalize(Sha3512MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD128MacBlobContextPtr RipeMD128MacInitialize()
    {
        return NULL;
    }

    void RipeMD128UMacpdate(RipeMD128MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* RipeMD128MacFinalize(RipeMD128MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD160MacBlobContextPtr RipeMD160MacInitialize()
    {
        return NULL;
    }

    void RipeMD160UMacpdate(RipeMD160MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* RipeMD160MacFinalize(RipeMD160MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD256MacBlobContextPtr RipeMD256MacInitialize()
    {
        return NULL;
    }

    void RipeMD256UMacpdate(RipeMD256MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* RipeMD256MacFinalize(RipeMD256MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
    RipeMD320MacBlobContextPtr RipeMD320MacInitialize()
    {
        return NULL;
    }

    void RipeMD320UMacpdate(RipeMD320MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* RipeMD320MacFinalize(RipeMD320MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Blake2BMacBlobContextPtr Blake2BMacInitialize()
    {
        return NULL;
    }

    void Blake2BUMacpdate(Blake2BMacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Blake2BMacFinalize(Blake2BMacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Blake2SMacBlobContextPtr Blake2SMacInitialize()
    {
        return NULL;
    }

    void Blake2SUMacpdate(Blake2SMacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Blake2SMacFinalize(Blake2SMacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
    TigerMacBlobContextPtr TigerMacInitialize()
    {
        return NULL;
    }

    void TigerUMacpdate(TigerMacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* TigerMacFinalize(TigerMacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Shake128MacBlobContextPtr Shake128MacInitialize()
    {
        return NULL;
    }

    void Shake128UMacpdate(Shake128MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Shake128MacFinalize(Shake128MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Shake256MacBlobContextPtr Shake256MacInitialize()
    {
        return NULL;
    }

    void Shake256UMacpdate(Shake256MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Shake256MacFinalize(Shake256MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Siphash64MacBlobContextPtr Siphash64MacInitialize()
    {
        return NULL;
    }

    void Siphash64UMacpdate(Siphash64MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Siphash64MacFinalize(Siphash64MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Siphash128MacBlobContextPtr Siphash128MacInitialize()
    {
        return NULL;
    }

    void Siphash128UMacpdate(Siphash128MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Siphash128MacFinalize(Siphash128MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh224MacBlobContextPtr Lsh224MacInitialize()
    {
        return NULL;
    }

    void Lsh224UMacpdate(Lsh224MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Lsh224MacFinalize(Lsh224MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh256MacBlobContextPtr Lsh256MacInitialize()
    {
        return NULL;
    }

    void Lsh256UMacpdate(Lsh256MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Lsh256MacFinalize(Lsh256MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh384MacBlobContextPtr Lsh384MacInitialize()
    {
        return NULL;
    }

    void Lsh384UMacpdate(Lsh384MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Lsh384MacFinalize(Lsh384MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Lsh512MacBlobContextPtr Lsh512MacInitialize()
    {
        return NULL;
    }

    void Lsh512UMacpdate(Lsh512MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Lsh512MacFinalize(Lsh512MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
    Sm3MacBlobContextPtr Sm3MacInitialize()
    {
        return NULL;
    }

    void Sm3UMacpdate(Sm3MacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* Sm3MacFinalize(Sm3MacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
    WhirlpoolMacBlobContextPtr WhirlpoolMacInitialize()
    {
        return NULL;
    }

    void WhirlpoolUMacpdate(WhirlpoolMacBlobContextPtr blobContext, const char* message, unsigned int length)
    {

    }

    const char* WhirlpoolMacFinalize(WhirlpoolMacBlobContextPtr blobContext)
    {
        return NULL;
    }
#endif

#ifdef __cplusplus
}
#endif