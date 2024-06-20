#include "crypto_mac.h"

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptlib.h>
#include <filters.h>
#include <md2.h>
#include <md4.h>
#include <md5.h>
#include <sha.h>
#include <sha3.h>
#include <ripemd.h>
#include <blake2.h>
#include <tiger.h>
#include <shake.h>
#include <siphash.h>
#include <lsh.h>
#include <sm3.h>
#include <whrlpool.h>
#include <cmac.h>
#include <secblock.h>
#include <osrng.h>
#include <hmac.h>
#include <cbcmac.h>
#include <dmac.h>
#include <gcm.h>
#include <poly1305.h>
#include <ttmac.h>
#include <vmac.h>
#include <aes.h>
#include <hex.h>
#include "algorithms.h"
#include "util.h"


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

// If CRYPTOPP_USE_AES_GENERATOR is 1 then AES/OFB based is used.
// Otherwise the OS random number generator is used.
#define CRYPTOPP_USE_AES_GENERATOR 1

using namespace CryptoPP;
using namespace Weak1;

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__MD2__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacMd2(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacMd2\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacMd2 Key is good\r\n");
        HMAC<MD2> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<MD2>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacMd2 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<MD2>::DIGESTSIZE,algo_hmac_md2 );
            if(result)
            {
                DebugMessage("DoMacMd2 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacMd2 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacMd2 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacMd2 key is NULL\r\n");
    }
    return NULL;
}
#endif

#if (defined(__MD4__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacMd4(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacMd4\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacMd4 Key is good\r\n");
        HMAC<MD4> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<MD4>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacMd4 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<MD4>::DIGESTSIZE,algo_hmac_md4 );
            if(result)
            {
                DebugMessage("DoMacMd4 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacMd4 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacMd4 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacMd4 key is NULL\r\n");
    }
    return NULL;
}
#endif

#if (defined(__MD5__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacMd5(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacMd5\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacMd5 Key is good\r\n");
        HMAC<MD5> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<MD5>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacMd5 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<MD5>::DIGESTSIZE,algo_hmac_md5 );
            if(result)
            {
                DebugMessage("DoMacMd5 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacMd5 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacMd5 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacMd5 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA1__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha1(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha1\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha1 Key is good\r\n");
        HMAC<SHA1> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA1>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha1 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA1>::DIGESTSIZE,algo_hmac_sha1 );
            if(result)
            {
                DebugMessage("DoMacSha1 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha1 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha1 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha1 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA224__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha224(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha224\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha224 Key is good\r\n");
        HMAC<SHA224> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA224>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha224 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA224>::DIGESTSIZE,algo_hmac_sha224 );
            if(result)
            {
                DebugMessage("DoMacSha224 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha224 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha224 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha224 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA256__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha256(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha256 Key is good\r\n");
        HMAC<SHA256> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA256>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha256 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA256>::DIGESTSIZE,algo_hmac_sha256 );
            if(result)
            {
                DebugMessage("DoMacSha256 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha256 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha256 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha256 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA384__)|| defined(__ALL__) )&& defined(__USE_MAC__)

const char * DoMacSha384(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha384\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha384 Key is good\r\n");
        HMAC<SHA384> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA384>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha384 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA384>::DIGESTSIZE,algo_hmac_sha384 );
            if(result)
            {
                DebugMessage("DoMacSha384 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha384 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha384 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha384 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA512__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha512(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha512\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha512 Key is good\r\n");
        HMAC<SHA512> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA512>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha512 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA512>::DIGESTSIZE,algo_hmac_sha512 );
            if(result)
            {
                DebugMessage("DoMacSha512 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha512 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha512 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha512 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA3224__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha3224(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha3224\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha3224 Key is good\r\n");
        HMAC<SHA3_224> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_224>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha3224 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_224>::DIGESTSIZE,algo_hmac_sha3_224 );
            if(result)
            {
                DebugMessage("DoMacSha3224 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha3224 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha3224 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha3224 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA3256__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha3256(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha3256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha3256 Key is good\r\n");
        HMAC<SHA3_256> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_256>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha3256 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_256>::DIGESTSIZE,algo_hmac_sha3_256 );
            if(result)
            {
                DebugMessage("DoMacSha3256 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha3256 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha3256 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha3256 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA3384__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha3384(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha3384\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha3384 Key is good\r\n");
        HMAC<SHA3_384> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_384>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha3384 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_384>::DIGESTSIZE,algo_hmac_sha3_384 );
            if(result)
            {
                DebugMessage("DoMacSha3384 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha3384 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha3384 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha3384 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHA3512__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSha3512(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSha3512\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSha3512 Key is good\r\n");
        HMAC<SHA3_512> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_512>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSha3512 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_512>::DIGESTSIZE,algo_hmac_sha3_512 );
            if(result)
            {
                DebugMessage("DoMacSha3512 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSha3512 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSha3512 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSha3512 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__RIPEMD128__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacRipeMd128(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacRipeMd128\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacRipeMd128 Key is good\r\n");
        HMAC<RIPEMD128> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD128>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacRipeMd128 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD128>::DIGESTSIZE,algo_hmac_ripemd_128 );
            if(result)
            {
                DebugMessage("DoMacRipeMd128 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacRipeMd128 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacRipeMd128 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacRipeMd128 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__RIPEMD160__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacRipeMd160(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacRipeMd160\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacRipeMd160 Key is good\r\n");
        HMAC<RIPEMD160> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD160>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacRipeMd160 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD160>::DIGESTSIZE,algo_hmac_ripemd_160 );
            if(result)
            {
                DebugMessage("DoMacRipeMd160 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacRipeMd160 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacRipeMd160 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacRipeMd160 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__RIPEMD256__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacRipeMd256(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacRipeMd256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacRipeMd256 Key is good\r\n");
        HMAC<RIPEMD256> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD256>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacRipeMd256 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD256>::DIGESTSIZE,algo_hmac_ripemd_256 );
            if(result)
            {
                DebugMessage("DoMacRipeMd256 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacRipeMd256 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacRipeMd256 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacRipeMd256 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__RIPEMD320__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacRipeMd320(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacRipeMd320\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacRipeMd320 Key is good\r\n");
        HMAC<RIPEMD320> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD320>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacRipeMd320 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD320>::DIGESTSIZE,algo_hmac_ripemd_320 );
            if(result)
            {
                DebugMessage("DoMacRipeMd320 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacRipeMd320 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacRipeMd320 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacRipeMd320 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__BLAKE2B__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacBlake2b(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacBlake2b\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacBlake2b Key is good\r\n");
        HMAC<BLAKE2b> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<BLAKE2b>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacBlake2b buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<BLAKE2b>::DIGESTSIZE,algo_blake2b );
            if(result)
            {
                DebugMessage("DoMacBlake2b tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacBlake2b tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacBlake2b failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacBlake2b key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__BLAKE2S__)|| defined(__ALL__)) && defined(__USE_MAC__)

extern "C" const char * DoMacBlake2s(const char * key, unsigned int length,  const char * message)
{
    DebugMessage("DoMacBlake2s\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacBlake2s Key is good\r\n");
        HMAC<BLAKE2s> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<BLAKE2s>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacBlake2s buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<BLAKE2s>::DIGESTSIZE,algo_blake2s );
            if(result)
            {
                DebugMessage("DoMacBlake2s tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacBlake2s tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacBlake2s failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacBlake2s key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__TIGER__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacTiger(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacTiger\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacTiger Key is good\r\n");
        HMAC<Tiger> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<Tiger>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacTiger buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<Tiger>::DIGESTSIZE,algo_hmac_tiger );
            if(result)
            {
                DebugMessage("DoMacTiger tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacTiger tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacTiger failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacTiger key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHAKE128__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacShake128(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacShake128\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacShake128 Key is good\r\n");
        HMAC<SHAKE128> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHAKE128>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacShake128 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHAKE128>::DIGESTSIZE,algo_hmac_shake_128 );
            if(result)
            {
                DebugMessage("DoMacShake128 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacShake128 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacShake128 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacShake128 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SHAKE256__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacShake256(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacShake256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacShake256 Key is good\r\n");
        HMAC<SHAKE256> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHAKE256>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacShake256 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHAKE256>::DIGESTSIZE,algo_hmac_shake_256 );
            if(result)
            {
                DebugMessage("DoMacShake256 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacShake256 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacShake256 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacShake256 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SIPHASH64__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSipHash64(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSipHash64\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSipHash64 Key is good\r\n");
        SipHash<2,4,false> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(SipHash<2,4,false>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSipHash64 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,SipHash<2,4,false>::DIGESTSIZE,algo_hmac_sip_hash64 );
            if(result)
            {
                DebugMessage("DoMacSipHash64 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSipHash64 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSipHash64 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSipHash64 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SIPHASH128__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSipHash128(const char * key, unsigned int length, const char * message)
{
     DebugMessage("DoMacSipHash128\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSipHash128 Key is good\r\n");
        SipHash<4,8,true> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(SipHash<4,8,true>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSipHash128 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,SipHash<4,8,true>::DIGESTSIZE,algo_hmac_sip_hash128 );
            if(result)
            {
                DebugMessage("DoMacSipHash128 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSipHash128 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSipHash128 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSipHash128 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__LSH224__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacLsh224(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacLsh224\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacLsh224 Key is good\r\n");
        HMAC<LSH224> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH224>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacLsh224 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH224>::DIGESTSIZE,algo_hmac_lsh_224 );
            if(result)
            {
                DebugMessage("DoMacLsh224 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacLsh224 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacLsh224 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacLsh224 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__LSH256__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacLsh256(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacLsh256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacLsh256 Key is good\r\n");
        HMAC<LSH256> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH256>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacLsh256 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH256>::DIGESTSIZE,algo_hmac_lsh_256 );
            if(result)
            {
                DebugMessage("DoMacLsh256 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacLsh256 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacLsh256 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacLsh256 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__LSH384__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacLsh384(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacLsh384\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacLsh384 Key is good\r\n");
        HMAC<LSH384> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH384>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacLsh384 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH384>::DIGESTSIZE,algo_hmac_lsh_384 );
            if(result)
            {
                DebugMessage("DoMacLsh384 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacLsh384 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacLsh384 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacLsh384 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__LSH512__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacLsh512(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacLsh512\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacLsh512 Key is good\r\n");
        HMAC<LSH512> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH512>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacLsh512 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH512>::DIGESTSIZE,algo_hmac_lsh_512 );
            if(result)
            {
                DebugMessage("DoMacLsh512 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacLsh512 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacLsh512 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacLsh512 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__SM3__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacSm3(const char * key, unsigned int length, const char * message)
{
    DebugMessage("DoMacSm3\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacSm3 Key is good\r\n");
        HMAC<SM3> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SM3>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacSm3 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SM3>::DIGESTSIZE,algo_hmac_sm3 );
            if(result)
            {
                DebugMessage("DoMacSm3 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacSm3 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacSm3 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacSm3 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__WHIRLPOOL__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacWhirlpool(const char * key, unsigned int length, const char * message)
{
     DebugMessage("DoMacWhirlpool\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacWhirlpool Key is good\r\n");
        HMAC<Whirlpool> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<Whirlpool>::DIGESTSIZE);
        if(lpBuffer)
        {
            DebugMessage("DoMacWhirlpool buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<Whirlpool>::DIGESTSIZE,algo_hmac_whirlpool );
            if(result)
            {
                DebugMessage("DoMacWhirlpool tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacWhirlpool tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacWhirlpool failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacWhirlpool key is NULL\r\n");
    }
    return NULL;
}

#endif

#if defined(__CMAC__)|| defined(__ALL__)

const char * DoMacCMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacCMac\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        DebugMessage("DoMacCMac Key is good\r\n");
        CMAC<AES> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(hmac.DigestSize());
        if(lpBuffer)
        {
            DebugMessage("DoMacCMac buffer is good\r\n");
            
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,hmac.DigestSize(),algo_cmac );
            if(result)
            {
                DebugMessage("DoMacCMac tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacCMac tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacCMac failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacCMac key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacCbcCMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacCbcCMac\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacCbcCMac Key is good\r\n");
        CBC_MAC<AES> hmac((CryptoPP::byte*)key, keyLength);
        hmac.Update((CryptoPP::byte*)message, strlen(message));

        lpBuffer = (char*)malloc(hmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacCbcCMac buffer is good\r\n");

            hmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, hmac.DigestSize(), algo_cbc_mac);
            if (result)
            {
                DebugMessage("DoMacCbcCMac tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacCbcCMac tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacCbcCMac failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacCbcCMac key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__DMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacDMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacDMac\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacDMac Key is good\r\n");
        DMAC<AES> hmac((CryptoPP::byte*)key, keyLength);
        hmac.Update((CryptoPP::byte*)message, strlen(message));

        lpBuffer = (char*)malloc(hmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacDMac buffer is good\r\n");

            hmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, hmac.DigestSize(), algo_dmac);
            if (result)
            {
                DebugMessage("DoMacDMac tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacDMac tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacDMac failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacDMac key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__GMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacGMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacGMac\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacGMac Key is good\r\n");
        GCM<AES>::Encryption hmac;

        SecByteBlock iv(AES::BLOCKSIZE);
        memset(iv, 0x00, iv.size());
        hmac.SetKeyWithIV((CryptoPP::byte*)key, keyLength,iv,iv.size() );
        

        hmac.Update((CryptoPP::byte*)message, strlen(message));

        lpBuffer = (char*)malloc(hmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacGMac buffer is good\r\n");

            hmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, hmac.DigestSize(), algo_gmac);
            if (result)
            {
                DebugMessage("DoMacGMac tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacGMac tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacGMac failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacGMac key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__HMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacHMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacHMac\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacHMac Key is good\r\n");
        HMAC<SHA256> hmac((CryptoPP::byte*)key, keyLength);
        hmac.Update((CryptoPP::byte*)message, strlen(message));

        lpBuffer = (char*)malloc(hmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacHMac buffer is good\r\n");

            hmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, hmac.DigestSize(), algo_hmac);
            if (result)
            {
                DebugMessage("DoMacHMac tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacHMac tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacHMac failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacHMac key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacPoly1305(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacPoly1305\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacPoly1305 Key is good\r\n");
        Poly1305<AES> hmac((CryptoPP::byte*)key, keyLength);
        hmac.Update((CryptoPP::byte*)message, strlen(message));

        lpBuffer = (char*)malloc(hmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacPoly1305 buffer is good\r\n");

            hmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, hmac.DigestSize(), algo_poly_1305);
            if (result)
            {
                DebugMessage("DoMacPoly1305 tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacPoly1305 tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacPoly1305 failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacPoly1305 key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacTwoTrack(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacTwoTrack\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacTwoTrack Key is good\r\n");
        TTMAC hmac((CryptoPP::byte*)key, keyLength);
        hmac.Update((CryptoPP::byte*)message, strlen(message));

        lpBuffer = (char*)malloc(hmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacTwoTrack buffer is good\r\n");

            hmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, hmac.DigestSize(), algo_two_track);
            if (result)
            {
                DebugMessage("DoMacTwoTrack tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacTwoTrack tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacTwoTrack failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacTwoTrack key is NULL\r\n");
    }
    return NULL;
}

#endif

#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

const char * DoMacVMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    DebugMessage("DoMacVMac\r\n");
    char* lpBuffer = NULL;
    const char* result;
    int keyLength = 0;
    if (key)
    {
        keyLength = length;
        DebugMessage("DoMacVMac Key is good\r\n");
        VMAC<AES,128> vmac;
        SecByteBlock iv(AES::BLOCKSIZE);
        memset(iv, 0x00, iv.size());
        vmac.SetKeyWithIV((CryptoPP::byte*)key, keyLength, iv, iv.size());
        vmac.Update((const CryptoPP::byte*)message, strlength(message));
        lpBuffer = (char*)malloc(vmac.DigestSize());
        if (lpBuffer)
        {
            DebugMessage("DoMacVMac buffer is good\r\n");

            vmac.Final((CryptoPP::byte*)lpBuffer);
            result = ToHex(lpBuffer, vmac.DigestSize(), algo_vmac);
            if (result)
            {
                DebugMessage("DoMacVMac tohex is good\r\n");
                return result;
            }
            else
            {
                DebugMessage("DoMacVMac tohex failed\r\n");
            }
        }
        else
        {
            DebugMessage("DoMacVMac failed to allocated memory\r\n");
        }
    }
    else
    {
        DebugMessage("DoMacVMac key is NULL\r\n");
    }
    return NULL;
}

#endif

#ifdef __cplusplus
}
#endif
