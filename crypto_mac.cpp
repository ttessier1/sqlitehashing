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
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

// If CRYPTOPP_USE_AES_GENERATOR is 1 then AES/OFB based is used.
// Otherwise the OS random number generator is used.
#define CRYPTOPP_USE_AES_GENERATOR 1

using namespace CryptoPP;
using namespace Weak1;

#ifdef __cplusplus
extern "C" {
#endif

const char * DoMacMd2(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacMd2\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacMd2 Key is good\r\n");
        HMAC<MD2> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<MD2>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacMd2 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<MD2>::DIGESTSIZE,algo_hmac_md2 );
            if(result)
            {
                OutputDebugStringA("DoMacMd2 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacMd2 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacMd2 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacMd2 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacMd4(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacMd4\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacMd4 Key is good\r\n");
        HMAC<MD4> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<MD4>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacMd4 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<MD4>::DIGESTSIZE,algo_hmac_md4 );
            if(result)
            {
                OutputDebugStringA("DoMacMd4 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacMd4 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacMd4 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacMd4 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacMd5(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacMd5\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacMd5 Key is good\r\n");
        HMAC<MD5> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<MD5>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacMd5 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<MD5>::DIGESTSIZE,algo_hmac_md5 );
            if(result)
            {
                OutputDebugStringA("DoMacMd5 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacMd5 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacMd5 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacMd5 key is NULL\r\n");
    }
    return NULL;
}
const char * DoMacSha1(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha1\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha1 Key is good\r\n");
        HMAC<SHA1> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA1>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha1 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA1>::DIGESTSIZE,algo_hmac_sha1 );
            if(result)
            {
                OutputDebugStringA("DoMacSha1 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha1 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha1 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha1 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha224(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha224\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha224 Key is good\r\n");
        HMAC<SHA224> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA224>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha224 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA224>::DIGESTSIZE,algo_hmac_sha224 );
            if(result)
            {
                OutputDebugStringA("DoMacSha224 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha224 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha224 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha224 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha256(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha256 Key is good\r\n");
        HMAC<SHA256> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA256>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha256 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA256>::DIGESTSIZE,algo_hmac_sha256 );
            if(result)
            {
                OutputDebugStringA("DoMacSha256 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha256 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha256 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha256 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha384(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha384\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha384 Key is good\r\n");
        HMAC<SHA384> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA384>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha384 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA384>::DIGESTSIZE,algo_hmac_sha384 );
            if(result)
            {
                OutputDebugStringA("DoMacSha384 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha384 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha384 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha384 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha512(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha512\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha512 Key is good\r\n");
        HMAC<SHA512> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA512>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha512 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA512>::DIGESTSIZE,algo_hmac_sha512 );
            if(result)
            {
                OutputDebugStringA("DoMacSha512 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha512 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha512 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha512 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha3224(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha3224\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha3224 Key is good\r\n");
        HMAC<SHA3_224> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_224>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha3224 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_224>::DIGESTSIZE,algo_hmac_sha3_224 );
            if(result)
            {
                OutputDebugStringA("DoMacSha3224 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha3224 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha3224 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha3224 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha3256(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha3256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha3256 Key is good\r\n");
        HMAC<SHA3_256> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_256>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha3256 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_256>::DIGESTSIZE,algo_hmac_sha3_256 );
            if(result)
            {
                OutputDebugStringA("DoMacSha3256 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha3256 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha3256 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha3256 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha3384(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha3384\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha3384 Key is good\r\n");
        HMAC<SHA3_384> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_384>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha3384 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_384>::DIGESTSIZE,algo_hmac_sha3_384 );
            if(result)
            {
                OutputDebugStringA("DoMacSha3384 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha3384 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha3384 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha3384 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSha3512(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSha3512\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSha3512 Key is good\r\n");
        HMAC<SHA3_512> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHA3_512>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSha3512 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHA3_512>::DIGESTSIZE,algo_hmac_sha3_512 );
            if(result)
            {
                OutputDebugStringA("DoMacSha3512 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSha3512 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSha3512 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSha3512 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacRipeMd128(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacRipeMd128\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacRipeMd128 Key is good\r\n");
        HMAC<RIPEMD128> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD128>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacRipeMd128 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD128>::DIGESTSIZE,algo_hmac_ripemd_128 );
            if(result)
            {
                OutputDebugStringA("DoMacRipeMd128 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacRipeMd128 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacRipeMd128 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacRipeMd128 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacRipeMd160(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacRipeMd160\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacRipeMd160 Key is good\r\n");
        HMAC<RIPEMD160> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD160>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacRipeMd160 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD160>::DIGESTSIZE,algo_hmac_ripemd_160 );
            if(result)
            {
                OutputDebugStringA("DoMacRipeMd160 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacRipeMd160 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacRipeMd160 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacRipeMd160 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacRipeMd256(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacRipeMd256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacRipeMd256 Key is good\r\n");
        HMAC<RIPEMD256> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD256>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacRipeMd256 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD256>::DIGESTSIZE,algo_hmac_ripemd_256 );
            if(result)
            {
                OutputDebugStringA("DoMacRipeMd256 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacRipeMd256 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacRipeMd256 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacRipeMd256 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacRipeMd320(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacRipeMd320\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacRipeMd320 Key is good\r\n");
        HMAC<RIPEMD320> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<RIPEMD320>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacRipeMd320 buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<RIPEMD320>::DIGESTSIZE,algo_hmac_ripemd_320 );
            if(result)
            {
                OutputDebugStringA("DoMacRipeMd320 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacRipeMd320 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacRipeMd320 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacRipeMd320 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacBlake2b(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacBlake2b\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    unsigned int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacBlake2b Key is good\r\n");
        HMAC<BLAKE2b> hmac (( CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<BLAKE2b>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacBlake2b buffer is good\r\n");
            hmac.Final((CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<BLAKE2b>::DIGESTSIZE,algo_blake2b );
            if(result)
            {
                OutputDebugStringA("DoMacBlake2b tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacBlake2b tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacBlake2b failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacBlake2b key is NULL\r\n");
    }
    return NULL;
}

extern "C" const char * DoMacBlake2s(const char * key, unsigned int length,  const char * message)
{
    OutputDebugStringA("DoMacBlake2s\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacBlake2s Key is good\r\n");
        HMAC<BLAKE2s> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<BLAKE2s>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacBlake2s buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<BLAKE2s>::DIGESTSIZE,algo_blake2b );
            if(result)
            {
                OutputDebugStringA("DoMacBlake2s tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacBlake2s tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacBlake2s failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacBlake2s key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacTiger(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacTiger\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacTiger Key is good\r\n");
        HMAC<Tiger> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<Tiger>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacTiger buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<Tiger>::DIGESTSIZE,algo_hmac_tiger );
            if(result)
            {
                OutputDebugStringA("DoMacTiger tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacTiger tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacTiger failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacTiger key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacShake128(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacShake128\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacShake128 Key is good\r\n");
        HMAC<SHAKE128> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHAKE128>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacShake128 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHAKE128>::DIGESTSIZE,algo_hmac_shake_128 );
            if(result)
            {
                OutputDebugStringA("DoMacShake128 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacShake128 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacShake128 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacShake128 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacShake256(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacShake256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacShake256 Key is good\r\n");
        HMAC<SHAKE256> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SHAKE256>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacShake256 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SHAKE256>::DIGESTSIZE,algo_hmac_shake_256 );
            if(result)
            {
                OutputDebugStringA("DoMacShake256 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacShake256 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacShake256 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacShake256 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSipHash64(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSipHash64\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSipHash64 Key is good\r\n");
        SipHash<2,4,false> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(SipHash<2,4,false>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSipHash64 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,SipHash<2,4,false>::DIGESTSIZE,algo_hmac_sip_hash64 );
            if(result)
            {
                OutputDebugStringA("DoMacSipHash64 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSipHash64 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSipHash64 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSipHash64 key is NULL\r\n");
    }
    return NULL;

}

const char * DoMacSipHash128(const char * key, unsigned int length, const char * message)
{
     OutputDebugStringA("DoMacSipHash128\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSipHash128 Key is good\r\n");
        SipHash<4,8,true> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(SipHash<4,8,true>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSipHash128 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,SipHash<4,8,true>::DIGESTSIZE,algo_hmac_sip_hash128 );
            if(result)
            {
                OutputDebugStringA("DoMacSipHash128 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSipHash128 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSipHash128 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSipHash128 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacLsh224(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacLsh224\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacLsh224 Key is good\r\n");
        HMAC<LSH224> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH224>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacLsh224 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH224>::DIGESTSIZE,algo_hmac_lsh_224 );
            if(result)
            {
                OutputDebugStringA("DoMacLsh224 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacLsh224 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacLsh224 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacLsh224 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacLsh256(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacLsh256\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacLsh256 Key is good\r\n");
        HMAC<LSH256> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH256>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacLsh256 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH256>::DIGESTSIZE,algo_hmac_lsh_256 );
            if(result)
            {
                OutputDebugStringA("DoMacLsh256 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacLsh256 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacLsh256 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacLsh256 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacLsh384(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacLsh384\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacLsh384 Key is good\r\n");
        HMAC<LSH384> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH384>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacLsh384 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH384>::DIGESTSIZE,algo_hmac_lsh_384 );
            if(result)
            {
                OutputDebugStringA("DoMacLsh384 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacLsh384 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacLsh384 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacLsh384 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacLsh512(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacLsh512\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacLsh512 Key is good\r\n");
        HMAC<LSH512> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<LSH512>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacLsh512 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<LSH512>::DIGESTSIZE,algo_hmac_lsh_512 );
            if(result)
            {
                OutputDebugStringA("DoMacLsh512 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacLsh512 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacLsh512 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacLsh512 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacSm3(const char * key, unsigned int length, const char * message)
{
    OutputDebugStringA("DoMacSm3\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacSm3 Key is good\r\n");
        HMAC<SM3> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<SM3>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacSm3 buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<SM3>::DIGESTSIZE,algo_hmac_sm3 );
            if(result)
            {
                OutputDebugStringA("DoMacSm3 tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacSm3 tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacSm3 failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacSm3 key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacWhirlpool(const char * key, unsigned int length, const char * message)
{
     OutputDebugStringA("DoMacWhirlpool\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacWhirlpool Key is good\r\n");
        HMAC<Whirlpool> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(HMAC<Whirlpool>::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacWhirlpool buffer is good\r\n");
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,HMAC<Whirlpool>::DIGESTSIZE,algo_hmac_whirlpool );
            if(result)
            {
                OutputDebugStringA("DoMacWhirlpool tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacWhirlpool tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacWhirlpool failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacWhirlpool key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacCMac(const char * key, unsigned int length, const char * message)
{
    AutoSeededRandomPool prng;
    OutputDebugStringA("DoMacCMac\r\n");
    char * lpBuffer = NULL;
    const char * result ; 
    int keyLength=0;
    if(key)
    {
        keyLength=length;
        OutputDebugStringA("DoMacCMac Key is good\r\n");
        CMAC<AES> hmac ((CryptoPP::byte *) key, keyLength);
        hmac.Update((CryptoPP::byte *)message,strlen(message));
        
        lpBuffer = (char * ) malloc(hmac.DigestSize());
        if(lpBuffer)
        {
            OutputDebugStringA("DoMacCMac buffer is good\r\n");
            
            hmac.Final(( CryptoPP::byte *)lpBuffer);
            result = ToHex(lpBuffer,hmac.DigestSize(),algo_hmac_cmac );
            if(result)
            {
                OutputDebugStringA("DoMacCMac tohex is good\r\n");
                return result;
            }
            else
            {
                OutputDebugStringA("DoMacCMac tohex failed\r\n");
            }
        }
        else
        {
            OutputDebugStringA("DoMacCMac failed to allocated memory\r\n");
        }
    }
    else
    {
        OutputDebugStringA("DoMacCMac key is NULL\r\n");
    }
    return NULL;
}

const char * DoMacCbcCMac(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

const char * DoMacDMac(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

const char * DoMacGMac(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

const char * DoMacHMac(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

const char * DoMacPoly1305(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

const char * DoMacTwoTrack(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

const char * DoMacVMac(const char * key, unsigned int length, const char * message)
{
    return NULL;
}

#ifdef __cplusplus
}
#endif
