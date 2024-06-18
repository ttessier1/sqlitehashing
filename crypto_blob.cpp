#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "crypto_blob.h"

#include <cryptlib.h>
#include <filters.h>

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


// Aggressive stack checking with VS2005 SP1 and above.
//#if (_MSC_FULL_VER >= 140050727)
//# pragma strict_gs_check (on)
//#endif

using namespace CryptoPP;
using namespace CryptoPP::Weak;

#if (defined(__MD2__) ||  defined(__MD4__) ||  defined(__MD5__) ||  defined (__ALL__)) && defined(__USE_BLOB__)



#if (defined(__MD2__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct md2BlobContext
{
    CryptoPP::Weak1::MD2* blobContext;
};
#endif

#if (defined(__MD4__) || defined(__ALL__))&& defined(__USE_BLOB__)
typedef struct md4BlobContext
{
    CryptoPP::Weak1::MD4* blobContext;
} Md4BlobBlobContext, * Md4BlobBlobContextPtr;
#endif

#if (defined(__MD5__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct md5BlobContext
{
    CryptoPP::Weak1::MD5* blobContext;
} Md5BlobContext, * Md5BlobContextPtr;
#endif

#endif


#if (defined(__SHA1__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha1BlobContext
{
    SHA1* blobContext;
} Sha1BlobContext, * Sha1BlobContextPtr;
#endif

#if (defined(__SHA224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha224BlobContext
{
    SHA224* blobContext;
} Sha224BlobContext, * Sha224BlobContextPtr;
#endif

#if (defined(__SHA256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha256BlobContext
{
    SHA256* blobContext;
} Sha256BlobContext, * Sha256BlobContextPtr;
#endif

#if (defined(__SHA384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha384BlobContext
{
    SHA384* blobContext;
} Sha384BlobContext, * Sha384BlobContextPtr;
#endif

#if (defined(__SHA512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha512BlobContext
{
    SHA512* blobContext;
} Sha512BlobContext, * Sha512BlobContextPtr;
#endif

#if (defined(__SHA3224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3224BlobContext
{
    SHA3_224* blobContext;
} Sha3224BlobContext, * Sha3224BlobContextPtr;
#endif

#if (defined(__SHA3256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3256BlobContext
{
    SHA3_256* blobContext;
} Sha3256BlobContext, * Sha3256BlobContextPtr;
#endif

#if (defined(__SHA3384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3384BlobContext
{
    SHA3_384* blobContext;
} Sha3384BlobContext, * Sha3384BlobContextPtr;
#endif

#if (defined(__SHA3512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3512BlobContext
{
    SHA3_512* blobContext;
} Sha3512BlobContext, * Sha3512BlobContextPtr;
#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD128BlobContext {
    RIPEMD128* blobContext;
}RipeMD128BlobContext, * RipeMD128BlobContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD160BlobContext {
    RIPEMD160* blobContext;
}RipeMD160BlobContext, * RipeMD160BlobContextPtr;
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD256BlobContext {
    RIPEMD256* blobContext;
}RipeMD256BlobContext, * RipeMD256BlobContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD320BlobContext {
    RIPEMD320* blobContext;
}RipeMD320BlobContext, * RipeMD320BlobContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2BBlobContext
{
    BLAKE2b* blobContext;
}Blake2BBlobContext, * Blake2BBlobContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2SBlobContext {
    BLAKE2s * blobContext;
}Blake2SBlobContext, * Blake2SBlobContextPtr;
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerBlobContext {
    Tiger* blobContext;
}TigerBlobContext, * TigerBlobContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake128BlobContext {
    SHAKE128* blobContext;
}Shake128BlobContext, * Shake128BlobContextPtr;
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake256BlobContext {
    SHAKE256* blobContext;
}Shake256BlobContext, * Shake256BlobContextPtr;
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash64BlobContext {
    SipHash<2, 4, false>* blobContext;
}Siphash64BlobContext, * Siphash64BlobContextPtr;
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash128BlobContext {
    SipHash<4, 8, true>* blobContext;
}Siphash128BlobContext, * Siphash128BlobContextPtr;
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh224BlobContext {
    LSH224* blobContext;
}Lsh224BlobContext, * Lsh224BlobContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh256BlobContext {
    LSH256* blobContext;
}Lsh256BlobContext, * Lsh256BlobContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh384BlobContext {
    LSH384* blobContext;
}Lsh384BlobContext, * Lsh384BlobContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh512BlobContext {
    LSH512* blobContext;
} Lsh512BlobContext, * Lsh512BlobContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sm3BlobContext {
    SM3* blobContext;
}Sm3BlobContext, * Sm3BlobContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct whirlpoolBlobContext {
    Whirlpool * blobContext;
}WhirlpoolBlobContext, * WhirlpoolBlobContextPtr;
#endif


#ifdef __cplusplus
extern "C" {
    

#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Md2BlobContextPtr Md2Initialize()
    {
        Md2BlobContextPtr blobContext = (Md2BlobContextPtr)malloc(sizeof(Md2BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Md2BlobContextPtr();
            blobContext->blobContext = (MD2*)malloc(sizeof(MD2));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) MD2();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Md2Update(Md2BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md2Finalize(Md2BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(MD2::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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
#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Md4BlobContextPtr Md4Initialize()
    {
        Md4BlobContextPtr blobContext = (Md4BlobContextPtr)malloc(sizeof(Md4BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Md4BlobContextPtr();
            blobContext->blobContext = (MD4*)malloc(sizeof(MD4));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) MD4();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Md4Update(Md4BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md4Finalize(Md4BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(MD4::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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
#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Md5BlobContextPtr Md5Initialize()
    {
        Md5BlobContextPtr blobContext = (Md5BlobContextPtr)malloc(sizeof(Md5BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Md5BlobContextPtr();
            blobContext->blobContext = (MD5*)malloc(sizeof(MD5));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) MD5();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Md5Update(Md5BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md5Finalize(Md5BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(MD5::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha1BlobContextPtr Sha1Initialize()
    {
        Sha1BlobContextPtr blobContext = (Sha1BlobContextPtr)malloc(sizeof(Sha1BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha1BlobContextPtr();
            blobContext->blobContext = (SHA1*)malloc(sizeof(SHA1));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA1();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha1Update(Sha1BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha1Finalize(Sha1BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA1::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha224BlobContextPtr Sha224Initialize()
    {
        Sha224BlobContextPtr blobContext = (Sha224BlobContextPtr)malloc(sizeof(Sha224BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha224BlobContextPtr();
            blobContext->blobContext = (SHA224*)malloc(sizeof(SHA224));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA224();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha224Update(Sha224BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha224Finalize(Sha224BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA224::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha256BlobContextPtr Sha256Initialize()
    {
        Sha256BlobContextPtr blobContext = (Sha256BlobContextPtr)malloc(sizeof(Sha256BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha256BlobContextPtr();
            blobContext->blobContext = (SHA256*)malloc(sizeof(SHA256));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA256();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha256Update(Sha256BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha256Finalize(Sha256BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA256::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha384BlobContextPtr Sha384Initialize()
    {
        Sha384BlobContextPtr blobContext = (Sha384BlobContextPtr)malloc(sizeof(Sha384BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha384BlobContextPtr();
            blobContext->blobContext = (SHA384*)malloc(sizeof(SHA384));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA384();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha384Update(Sha384BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha384Finalize(Sha384BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA384::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha512BlobContextPtr Sha512Initialize()
    {
        Sha512BlobContextPtr blobContext = (Sha512BlobContextPtr)malloc(sizeof(Sha512BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha512BlobContextPtr();
            blobContext->blobContext = (SHA512*)malloc(sizeof(SHA512));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA512();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha512Update(Sha512BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha512Finalize(Sha512BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA512::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3224BlobContextPtr Sha3224Initialize()
    {
        Sha3224BlobContextPtr blobContext = (Sha3224BlobContextPtr)malloc(sizeof(Sha3224BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha3224BlobContextPtr();
            blobContext->blobContext = (SHA3_224*)malloc(sizeof(SHA3_224));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA3_224();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha3224Update(Sha3224BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3224Finalize(Sha3224BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_224::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3256BlobContextPtr Sha3256Initialize()
    {
        Sha3256BlobContextPtr blobContext = (Sha3256BlobContextPtr)malloc(sizeof(Sha3256BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha3256BlobContextPtr();
            blobContext->blobContext = (SHA3_256*)malloc(sizeof(SHA3_256));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA3_256();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha3256Update(Sha3256BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3256Finalize(Sha3256BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_256::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3384BlobContextPtr Sha3384Initialize()
    {
        Sha3384BlobContextPtr blobContext = (Sha3384BlobContextPtr)malloc(sizeof(Sha3384BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha3384BlobContextPtr();
            blobContext->blobContext = (SHA3_384*)malloc(sizeof(SHA3_384));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA3_384();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha3384Update(Sha3384BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3384Finalize(Sha3384BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_384::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3512BlobContextPtr Sha3512Initialize()
    {
        Sha3512BlobContextPtr blobContext = (Sha3512BlobContextPtr)malloc(sizeof(Sha3512BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sha3512BlobContextPtr();
            blobContext->blobContext = (SHA3_512*)malloc(sizeof(SHA3_512));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHA3_512();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sha3512Update(Sha3512BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3512Finalize(Sha3512BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_512::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    RipeMD128BlobContextPtr RipeMD128Initialize()
    {
        RipeMD128BlobContextPtr blobContext = (RipeMD128BlobContextPtr)malloc(sizeof(RipeMD128BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)RipeMD128BlobContextPtr();
            blobContext->blobContext = (RIPEMD128*)malloc(sizeof(RIPEMD128));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) RIPEMD128();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void RipeMD128Update(RipeMD128BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD128Finalize(RipeMD128BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD128::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    RipeMD160BlobContextPtr RipeMD160Initialize()
    {
        RipeMD160BlobContextPtr blobContext = (RipeMD160BlobContextPtr)malloc(sizeof(RipeMD160BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)RipeMD160BlobContextPtr();
            blobContext->blobContext = (RIPEMD160*)malloc(sizeof(RIPEMD160));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) RIPEMD160();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void RipeMD160Update(RipeMD160BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD160Finalize(RipeMD160BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD160::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    RipeMD256BlobContextPtr RipeMD256Initialize()
    {
        RipeMD256BlobContextPtr blobContext = (RipeMD256BlobContextPtr)malloc(sizeof(RipeMD256BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)RipeMD256BlobContextPtr();
            blobContext->blobContext = (RIPEMD256*)malloc(sizeof(RIPEMD256));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) RIPEMD256();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void RipeMD256Update(RipeMD256BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD256Finalize(RipeMD256BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD256::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    RipeMD320BlobContextPtr RipeMD320Initialize()
    {
        RipeMD320BlobContextPtr blobContext = (RipeMD320BlobContextPtr)malloc(sizeof(RipeMD320BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)RipeMD320BlobContextPtr();
            blobContext->blobContext = (RIPEMD320*)malloc(sizeof(RIPEMD320));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) RIPEMD320();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void RipeMD320Update(RipeMD320BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD320Finalize(RipeMD320BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD320::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Blake2BBlobContextPtr Blake2BInitialize()
    {
        Blake2BBlobContextPtr blobContext = (Blake2BBlobContextPtr)malloc(sizeof(Blake2BBlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Blake2BBlobContextPtr();
            blobContext->blobContext = (BLAKE2b*)malloc(sizeof(BLAKE2b));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) BLAKE2b();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Blake2BUpdate(Blake2BBlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Blake2BFinalize(Blake2BBlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(BLAKE2b::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Blake2SBlobContextPtr Blake2SInitialize()
    {
        Blake2SBlobContextPtr blobContext = (Blake2SBlobContextPtr)malloc(sizeof(Blake2SBlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Blake2SBlobContextPtr();
            blobContext->blobContext = (BLAKE2s*)malloc(sizeof(BLAKE2s));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) BLAKE2s();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Blake2SUpdate(Blake2SBlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Blake2SFinalize(Blake2SBlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(BLAKE2s::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    TigerBlobContextPtr TigerInitialize()
    {
        TigerBlobContextPtr blobContext = (TigerBlobContextPtr)malloc(sizeof(TigerBlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)TigerBlobContextPtr();
            blobContext->blobContext = (Tiger*)malloc(sizeof(Tiger));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) Tiger();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void TigerUpdate(TigerBlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* TigerFinalize(TigerBlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(Tiger::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Shake128BlobContextPtr Shake128Initialize()
    {
        Shake128BlobContextPtr blobContext = (Shake128BlobContextPtr)malloc(sizeof(Shake128BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Shake128BlobContextPtr();
            blobContext->blobContext = (SHAKE128*)malloc(sizeof(SHAKE128));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHAKE128();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Shake128Update(Shake128BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Shake128Finalize(Shake128BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHAKE128::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Shake256BlobContextPtr Shake256Initialize()
    {
        Shake256BlobContextPtr blobContext = (Shake256BlobContextPtr)malloc(sizeof(Shake256BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Shake256BlobContextPtr();
            blobContext->blobContext = (SHAKE256*)malloc(sizeof(SHAKE256));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SHAKE256();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Shake256Update(Shake256BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Shake256Finalize(Shake256BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SHAKE256::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Siphash64BlobContextPtr Siphash64Initialize()
    {
        Siphash64BlobContextPtr blobContext = (Siphash64BlobContextPtr)malloc(sizeof(Siphash64BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Siphash64BlobContextPtr();
            blobContext->blobContext = (SipHash<2, 4, false>*)malloc(sizeof(SipHash<2, 4, false>));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SipHash<2, 4, false>();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Siphash64Update(Siphash64BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Siphash64Finalize(Siphash64BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SipHash<2, 4, false>::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Siphash128BlobContextPtr Siphash128Initialize()
    {
        Siphash128BlobContextPtr blobContext = (Siphash128BlobContextPtr)malloc(sizeof(Siphash128BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Siphash128BlobContextPtr();
            blobContext->blobContext = (SipHash<4, 8, true>*)malloc(sizeof(SipHash<4, 8, true>));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SipHash<4, 8, true>();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Siphash128Update(Siphash128BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Siphash128Finalize(Siphash128BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SipHash<4, 8, true>::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Lsh224BlobContextPtr Lsh224Initialize()
    {
        Lsh224BlobContextPtr blobContext = (Lsh224BlobContextPtr)malloc(sizeof(Lsh224BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Lsh224BlobContextPtr();
            blobContext->blobContext = (LSH224*)malloc(sizeof(LSH224));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) LSH224();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Lsh224Update(Lsh224BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh224Finalize(Lsh224BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH224::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Lsh256BlobContextPtr Lsh256Initialize()
    {
        Lsh256BlobContextPtr blobContext = (Lsh256BlobContextPtr)malloc(sizeof(Lsh256BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Lsh256BlobContextPtr();
            blobContext->blobContext = (LSH256*)malloc(sizeof(LSH256));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) LSH256();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Lsh256Update(Lsh256BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh256Finalize(Lsh256BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH256::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Lsh384BlobContextPtr Lsh384Initialize()
    {
        Lsh384BlobContextPtr blobContext = (Lsh384BlobContextPtr)malloc(sizeof(Lsh384BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Lsh384BlobContextPtr();
            blobContext->blobContext = (LSH384*)malloc(sizeof(LSH384));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) LSH384();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Lsh384Update(Lsh384BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh384Finalize(Lsh384BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH384::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Lsh512BlobContextPtr Lsh512Initialize()
    {
        Lsh512BlobContextPtr blobContext = (Lsh512BlobContextPtr)malloc(sizeof(Lsh512BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Lsh512BlobContextPtr();
            blobContext->blobContext = (LSH512*)malloc(sizeof(LSH512));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) LSH512();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Lsh512Update(Lsh512BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh512Finalize(Lsh512BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(LSH512::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    Sm3BlobContextPtr Sm3Initialize()
    {
        Sm3BlobContextPtr blobContext = (Sm3BlobContextPtr)malloc(sizeof(Sm3BlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)Sm3BlobContextPtr();
            blobContext->blobContext = (SM3*)malloc(sizeof(SM3));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) SM3();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void Sm3Update(Sm3BlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sm3Finalize(Sm3BlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(SM3::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

    WhirlpoolBlobContextPtr WhirlpoolInitialize()
    {
        WhirlpoolBlobContextPtr blobContext = (WhirlpoolBlobContextPtr)malloc(sizeof(WhirlpoolBlobContext));
        if (blobContext != NULL)
        {
            new(blobContext)WhirlpoolBlobContextPtr();
            blobContext->blobContext = (Whirlpool*)malloc(sizeof(Whirlpool));
            if (blobContext->blobContext)
            {
                new(blobContext->blobContext) Whirlpool();
            }
            else
            {
                free(blobContext);
                blobContext = NULL;
            }
        }
        return blobContext;
    }

    void WhirlpoolUpdate(WhirlpoolBlobContextPtr blobContext, const char* message, unsigned int length)
    {
        if (blobContext != NULL && blobContext->blobContext != NULL && message != NULL)
        {
            blobContext->blobContext->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* WhirlpoolFinalize(WhirlpoolBlobContextPtr blobContext)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (blobContext != NULL && blobContext->blobContext != NULL)
        {
            lpBuffer = (char*)malloc(Whirlpool::DIGESTSIZE);
            if (lpBuffer)
            {
                blobContext->blobContext->Final((CryptoPP::byte*)lpBuffer);
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

}
#endif