#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#define __WINDOWS_BCRYPT__

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

#if defined(__MD128__) ||defined(__MD160__) ||defined(__MD256__) ||defined(__MD256__) || defined(__ALL__)
#if defined(__MD128__) ||defined (__ALL__)
#pragma message( "MD128 Set")
#else
#pragma message( "MD128 NOT Set")
#endif
#if defined(__MD160__) ||defined (__ALL__)
#pragma message( "MD160 Set")
#else
#pragma message( "MD160 NOT Set")
#endif
#if defined(__MD256__) ||defined (__ALL__)
#pragma message( "MD256 Set")
#else
#pragma message( "MD256 NOT Set")
#endif
#if defined(__MD256__) ||defined (__ALL__)
#pragma message( "MD256 Set")
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

#if (defined(__MD2__) ||  defined(__MD4__) ||  defined(__MD5__) ||  defined (__ALL__)) && defined(__USE_BLOB__)

using namespace CryptoPP::Weak;

#if (defined(__MD2__) ||  defined (__ALL__))&& defined(__USE_BLOB__)
struct md2Context
{
    CryptoPP::Weak1::MD2* context;
};
#endif

#if (defined(__MD4__) || defined(__ALL__))&& defined(__USE_BLOB__)
typedef struct md4Context
{
    CryptoPP::Weak1::MD4* context;
} Md4Context, * Md4ContextPtr;
#endif

#if (defined(__MD5__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct md5Context
{
    CryptoPP::Weak1::MD5* context;
} Md5Context, * Md5ContextPtr;
#endif

#endif


#if (defined(__SHA1__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha1Context
{
    SHA1* context;
} Sha1Context, * Sha1ContextPtr;
#endif

#if (defined(__SHA224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha224Context
{
    SHA224* context;
} Sha224Context, * Sha224ContextPtr;
#endif

#if (defined(__SHA256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha256Context
{
    SHA256* context;
} Sha256Context, * Sha256ContextPtr;
#endif

#if (defined(__SHA384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha384Context
{
    SHA384* context;
} Sha384Context, * Sha384ContextPtr;
#endif

#if (defined(__SHA512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha512Context
{
    SHA512* context;
} Sha512Context, * Sha512ContextPtr;
#endif

#if (defined(__SHA3224__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3224Context
{
    SHA3_224* context;
} Sha3224Context, * Sha3224ContextPtr;
#endif

#if (defined(__SHA3256__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3256Context
{
    SHA3_256* context;
} Sha3256Context, * Sha3256ContextPtr;
#endif

#if (defined(__SHA3384__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3384Context
{
    SHA3_384* context;
} Sha3384Context, * Sha3384ContextPtr;
#endif

#if (defined(__SHA3512__)||defined(__ALL__)) && defined(__USE_BLOB__)
typedef struct sha3512Context
{
    SHA3_512* context;
} Sha3512Context, * Sha3512ContextPtr;
#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD128Context {
    RIPEMD128* context;
}RipeMD128Context, * RipeMD128ContextPtr;
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD160Context {
    RIPEMD160* context;
}RipeMD160Context, * RipeMD160ContextPtr;
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD256Context {
    RIPEMD256* context;
}RipeMD256Context, * RipeMD256ContextPtr;
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct ripeMD320Context {
    RIPEMD320* context;
}RipeMD320Context, * RipeMD320ContextPtr;
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2BContext
{
    BLAKE2b* context;
}Blake2BContext, * Blake2BContextPtr;
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct blake2SContext {
    BLAKE2s * context;
}Blake2SContext, * Blake2SContextPtr;
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct tigerContext {
    Tiger* context;
}TigerContext, * TigerContextPtr;
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake128Context {
    SHAKE128* context;
}Shake128Context, * Shake128ContextPtr;
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct shake256Context {
    SHAKE256* context;
}Shake256Context, * Shake256ContextPtr;
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash64Context {
    SipHash<2, 4, false>* context;
}Siphash64Context, * Siphash64ContextPtr;
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct siphash128Context {
    SipHash<4, 8, true>* context;
}Siphash128Context, * Siphash128ContextPtr;
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh224Context {
    LSH224* context;
}Lsh224Context, * Lsh224ContextPtr;
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh256Context {
    LSH256* context;
}Lsh256Context, * Lsh256ContextPtr;
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh384Context {
    LSH384* context;
}Lsh384Context, * Lsh384ContextPtr;
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct lsh512Context {
    LSH512* context;
} Lsh512Context, * Lsh512ContextPtr;
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct sm3Context {
    SM3* context;
}Sm3Context, * Sm3ContextPtr;
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
typedef struct whirlpoolContext {
    Whirlpool * context;
}WhirlpoolContext, * WhirlpoolContextPtr;
#endif


#ifdef __cplusplus
extern "C" {
    

#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Md2ContextPtr Md2Initialize()
    {
        Md2ContextPtr context = (Md2ContextPtr)malloc(sizeof(Md2Context));
        if (context != NULL)
        {
            new(context)Md2ContextPtr();
            context->context = (MD2*)malloc(sizeof(MD2));
            if (context->context)
            {
                new(context->context) MD2();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Md2Update(Md2ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md2Finalize(Md2ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(MD2::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif 
#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Md4ContextPtr Md4Initialize()
    {
        Md4ContextPtr context = (Md4ContextPtr)malloc(sizeof(Md4Context));
        if (context != NULL)
        {
            new(context)Md4ContextPtr();
            context->context = (MD4*)malloc(sizeof(MD4));
            if (context->context)
            {
                new(context->context) MD4();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Md4Update(Md4ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md4Finalize(Md4ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(MD4::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif
#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Md5ContextPtr Md5Initialize()
    {
        Md5ContextPtr context = (Md5ContextPtr)malloc(sizeof(Md5Context));
        if (context != NULL)
        {
            new(context)Md5ContextPtr();
            context->context = (MD5*)malloc(sizeof(MD5));
            if (context->context)
            {
                new(context->context) MD5();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Md5Update(Md5ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Md5Finalize(Md5ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(MD5::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha1ContextPtr Sha1Initialize()
    {
        Sha1ContextPtr context = (Sha1ContextPtr)malloc(sizeof(Sha1Context));
        if (context != NULL)
        {
            new(context)Sha1ContextPtr();
            context->context = (SHA1*)malloc(sizeof(SHA1));
            if (context->context)
            {
                new(context->context) SHA1();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha1Update(Sha1ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha1Finalize(Sha1ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA1::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha224ContextPtr Sha224Initialize()
    {
        Sha224ContextPtr context = (Sha224ContextPtr)malloc(sizeof(Sha224Context));
        if (context != NULL)
        {
            new(context)Sha224ContextPtr();
            context->context = (SHA224*)malloc(sizeof(SHA224));
            if (context->context)
            {
                new(context->context) SHA224();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha224Update(Sha224ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha224Finalize(Sha224ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA224::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha256ContextPtr Sha256Initialize()
    {
        Sha256ContextPtr context = (Sha256ContextPtr)malloc(sizeof(Sha256Context));
        if (context != NULL)
        {
            new(context)Sha256ContextPtr();
            context->context = (SHA256*)malloc(sizeof(SHA256));
            if (context->context)
            {
                new(context->context) SHA256();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha256Update(Sha256ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha256Finalize(Sha256ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA256::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha384ContextPtr Sha384Initialize()
    {
        Sha384ContextPtr context = (Sha384ContextPtr)malloc(sizeof(Sha384Context));
        if (context != NULL)
        {
            new(context)Sha384ContextPtr();
            context->context = (SHA384*)malloc(sizeof(SHA384));
            if (context->context)
            {
                new(context->context) SHA384();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha384Update(Sha384ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha384Finalize(Sha384ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA384::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)


    Sha512ContextPtr Sha512Initialize()
    {
        Sha512ContextPtr context = (Sha512ContextPtr)malloc(sizeof(Sha512Context));
        if (context != NULL)
        {
            new(context)Sha512ContextPtr();
            context->context = (SHA512*)malloc(sizeof(SHA512));
            if (context->context)
            {
                new(context->context) SHA512();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha512Update(Sha512ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha512Finalize(Sha512ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA512::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif

#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3224ContextPtr Sha3224Initialize()
    {
        Sha3224ContextPtr context = (Sha3224ContextPtr)malloc(sizeof(Sha3224Context));
        if (context != NULL)
        {
            new(context)Sha3224ContextPtr();
            context->context = (SHA3_224*)malloc(sizeof(SHA3_224));
            if (context->context)
            {
                new(context->context) SHA3_224();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha3224Update(Sha3224ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3224Finalize(Sha3224ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_224::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3256ContextPtr Sha3256Initialize()
    {
        Sha3256ContextPtr context = (Sha3256ContextPtr)malloc(sizeof(Sha3256Context));
        if (context != NULL)
        {
            new(context)Sha3256ContextPtr();
            context->context = (SHA3_256*)malloc(sizeof(SHA3_256));
            if (context->context)
            {
                new(context->context) SHA3_256();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha3256Update(Sha3256ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3256Finalize(Sha3256ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_256::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3384ContextPtr Sha3384Initialize()
    {
        Sha3384ContextPtr context = (Sha3384ContextPtr)malloc(sizeof(Sha3384Context));
        if (context != NULL)
        {
            new(context)Sha3384ContextPtr();
            context->context = (SHA3_384*)malloc(sizeof(SHA3_384));
            if (context->context)
            {
                new(context->context) SHA3_384();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha3384Update(Sha3384ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3384Finalize(Sha3384ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_384::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sha3512ContextPtr Sha3512Initialize()
    {
        Sha3512ContextPtr context = (Sha3512ContextPtr)malloc(sizeof(Sha3512Context));
        if (context != NULL)
        {
            new(context)Sha3512ContextPtr();
            context->context = (SHA3_512*)malloc(sizeof(SHA3_512));
            if (context->context)
            {
                new(context->context) SHA3_512();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sha3512Update(Sha3512ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sha3512Finalize(Sha3512ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHA3_512::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)

    RipeMD128ContextPtr RipeMD128Initialize()
    {
        RipeMD128ContextPtr context = (RipeMD128ContextPtr)malloc(sizeof(RipeMD128Context));
        if (context != NULL)
        {
            new(context)RipeMD128ContextPtr();
            context->context = (RIPEMD128*)malloc(sizeof(RIPEMD128));
            if (context->context)
            {
                new(context->context) RIPEMD128();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void RipeMD128Update(RipeMD128ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD128Finalize(RipeMD128ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD128::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)

    RipeMD160ContextPtr RipeMD160Initialize()
    {
        RipeMD160ContextPtr context = (RipeMD160ContextPtr)malloc(sizeof(RipeMD160Context));
        if (context != NULL)
        {
            new(context)RipeMD160ContextPtr();
            context->context = (RIPEMD160*)malloc(sizeof(RIPEMD160));
            if (context->context)
            {
                new(context->context) RIPEMD160();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void RipeMD160Update(RipeMD160ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD160Finalize(RipeMD160ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD160::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)

    RipeMD256ContextPtr RipeMD256Initialize()
    {
        RipeMD256ContextPtr context = (RipeMD256ContextPtr)malloc(sizeof(RipeMD256Context));
        if (context != NULL)
        {
            new(context)RipeMD256ContextPtr();
            context->context = (RIPEMD256*)malloc(sizeof(RIPEMD256));
            if (context->context)
            {
                new(context->context) RIPEMD256();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void RipeMD256Update(RipeMD256ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD256Finalize(RipeMD256ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD256::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)

    RipeMD320ContextPtr RipeMD320Initialize()
    {
        RipeMD320ContextPtr context = (RipeMD320ContextPtr)malloc(sizeof(RipeMD320Context));
        if (context != NULL)
        {
            new(context)RipeMD320ContextPtr();
            context->context = (RIPEMD320*)malloc(sizeof(RIPEMD320));
            if (context->context)
            {
                new(context->context) RIPEMD320();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void RipeMD320Update(RipeMD320ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* RipeMD320Finalize(RipeMD320ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(RIPEMD320::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Blake2BContextPtr Blake2BInitialize()
    {
        Blake2BContextPtr context = (Blake2BContextPtr)malloc(sizeof(Blake2BContext));
        if (context != NULL)
        {
            new(context)Blake2BContextPtr();
            context->context = (BLAKE2b*)malloc(sizeof(BLAKE2b));
            if (context->context)
            {
                new(context->context) BLAKE2b();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Blake2BUpdate(Blake2BContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Blake2BFinalize(Blake2BContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(BLAKE2b::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Blake2SContextPtr Blake2SInitialize()
    {
        Blake2SContextPtr context = (Blake2SContextPtr)malloc(sizeof(Blake2SContext));
        if (context != NULL)
        {
            new(context)Blake2SContextPtr();
            context->context = (BLAKE2s*)malloc(sizeof(BLAKE2s));
            if (context->context)
            {
                new(context->context) BLAKE2s();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Blake2SUpdate(Blake2SContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Blake2SFinalize(Blake2SContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(BLAKE2s::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)

    TigerContextPtr TigerInitialize()
    {
        TigerContextPtr context = (TigerContextPtr)malloc(sizeof(TigerContext));
        if (context != NULL)
        {
            new(context)TigerContextPtr();
            context->context = (Tiger*)malloc(sizeof(Tiger));
            if (context->context)
            {
                new(context->context) Tiger();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void TigerUpdate(TigerContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* TigerFinalize(TigerContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(Tiger::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Shake128ContextPtr Shake128Initialize()
    {
        Shake128ContextPtr context = (Shake128ContextPtr)malloc(sizeof(Shake128Context));
        if (context != NULL)
        {
            new(context)Shake128ContextPtr();
            context->context = (SHAKE128*)malloc(sizeof(SHAKE128));
            if (context->context)
            {
                new(context->context) SHAKE128();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Shake128Update(Shake128ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Shake128Finalize(Shake128ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHAKE128::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Shake256ContextPtr Shake256Initialize()
    {
        Shake256ContextPtr context = (Shake256ContextPtr)malloc(sizeof(Shake256Context));
        if (context != NULL)
        {
            new(context)Shake256ContextPtr();
            context->context = (SHAKE256*)malloc(sizeof(SHAKE256));
            if (context->context)
            {
                new(context->context) SHAKE256();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Shake256Update(Shake256ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Shake256Finalize(Shake256ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SHAKE256::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Siphash64ContextPtr Siphash64Initialize()
    {
        Siphash64ContextPtr context = (Siphash64ContextPtr)malloc(sizeof(Siphash64Context));
        if (context != NULL)
        {
            new(context)Siphash64ContextPtr();
            context->context = (SipHash<2, 4, false>*)malloc(sizeof(SipHash<2, 4, false>));
            if (context->context)
            {
                new(context->context) SipHash<2, 4, false>();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Siphash64Update(Siphash64ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Siphash64Finalize(Siphash64ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SipHash<2, 4, false>::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Siphash128ContextPtr Siphash128Initialize()
    {
        Siphash128ContextPtr context = (Siphash128ContextPtr)malloc(sizeof(Siphash128Context));
        if (context != NULL)
        {
            new(context)Siphash128ContextPtr();
            context->context = (SipHash<4, 8, true>*)malloc(sizeof(SipHash<4, 8, true>));
            if (context->context)
            {
                new(context->context) SipHash<4, 8, true>();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Siphash128Update(Siphash128ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Siphash128Finalize(Siphash128ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SipHash<4, 8, true>::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif


#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Lsh224ContextPtr Lsh224Initialize()
    {
        Lsh224ContextPtr context = (Lsh224ContextPtr)malloc(sizeof(Lsh224Context));
        if (context != NULL)
        {
            new(context)Lsh224ContextPtr();
            context->context = (LSH224*)malloc(sizeof(LSH224));
            if (context->context)
            {
                new(context->context) LSH224();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Lsh224Update(Lsh224ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh224Finalize(Lsh224ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(LSH224::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Lsh256ContextPtr Lsh256Initialize()
    {
        Lsh256ContextPtr context = (Lsh256ContextPtr)malloc(sizeof(Lsh256Context));
        if (context != NULL)
        {
            new(context)Lsh256ContextPtr();
            context->context = (LSH256*)malloc(sizeof(LSH256));
            if (context->context)
            {
                new(context->context) LSH256();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Lsh256Update(Lsh256ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh256Finalize(Lsh256ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(LSH256::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Lsh384ContextPtr Lsh384Initialize()
    {
        Lsh384ContextPtr context = (Lsh384ContextPtr)malloc(sizeof(Lsh384Context));
        if (context != NULL)
        {
            new(context)Lsh384ContextPtr();
            context->context = (LSH384*)malloc(sizeof(LSH384));
            if (context->context)
            {
                new(context->context) LSH384();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Lsh384Update(Lsh384ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh384Finalize(Lsh384ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(LSH384::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Lsh512ContextPtr Lsh512Initialize()
    {
        Lsh512ContextPtr context = (Lsh512ContextPtr)malloc(sizeof(Lsh512Context));
        if (context != NULL)
        {
            new(context)Lsh512ContextPtr();
            context->context = (LSH512*)malloc(sizeof(LSH512));
            if (context->context)
            {
                new(context->context) LSH512();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Lsh512Update(Lsh512ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Lsh512Finalize(Lsh512ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(LSH512::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)

    Sm3ContextPtr Sm3Initialize()
    {
        Sm3ContextPtr context = (Sm3ContextPtr)malloc(sizeof(Sm3Context));
        if (context != NULL)
        {
            new(context)Sm3ContextPtr();
            context->context = (SM3*)malloc(sizeof(SM3));
            if (context->context)
            {
                new(context->context) SM3();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void Sm3Update(Sm3ContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* Sm3Finalize(Sm3ContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(SM3::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)

    WhirlpoolContextPtr WhirlpoolInitialize()
    {
        WhirlpoolContextPtr context = (WhirlpoolContextPtr)malloc(sizeof(WhirlpoolContext));
        if (context != NULL)
        {
            new(context)WhirlpoolContextPtr();
            context->context = (Whirlpool*)malloc(sizeof(Whirlpool));
            if (context->context)
            {
                new(context->context) Whirlpool();
            }
            else
            {
                free(context);
                context = NULL;
            }
        }
        return context;
    }

    void WhirlpoolUpdate(WhirlpoolContextPtr context, const char* message, unsigned int length)
    {
        if (context != NULL && context->context != NULL && message != NULL)
        {
            context->context->Update((CryptoPP::byte*)message, length);
        }
    }

    const char* WhirlpoolFinalize(WhirlpoolContextPtr context)
    {
        char* lpBuffer = NULL;
        const char* result = NULL;;
        if (context != NULL && context->context != NULL)
        {
            lpBuffer = (char*)malloc(Whirlpool::DIGESTSIZE);
            if (lpBuffer)
            {
                context->context->Final((CryptoPP::byte*)lpBuffer);
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
            DebugMessage("Invalid Context\r\n");
        }
        return result;
    }

#endif

}
#endif