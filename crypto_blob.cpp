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



#if defined(__MD2__) ||  defined(__MD4__) ||  defined(__MD5__) ||  (defined __ALL__)

using namespace CryptoPP::Weak;

typedef struct md2Context
{
    CryptoPP::Weak1::MD2* context;
} Md5Context, * Md5ContextPtr;


#endif


//SHA1 * g_sha = NULL ;

#ifdef __cplusplus
extern "C" {
    

#if defined(__MD2__) || (defined __ALL__)


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
                        DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlen(result), (MD2::DIGESTSIZE * 2), result);
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