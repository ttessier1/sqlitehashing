#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "crypto.h"
//#include "dll.h"
#include <cryptlib.h>
//#include <aes.h>
#include <filters.h>
//#include <md5.h>
#include <md2.h>
#include <md4.h>
#include <md5.h>
#include <panama.h>
#include <des.h>
#include <arc4.h>
#include <seal.h>
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
#include <hex.h>
#include "algorithms.h"
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
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

// If CRYPTOPP_USE_AES_GENERATOR is 1 then AES/OFB based is used.
// Otherwise the OS random number generator is used.
#define CRYPTOPP_USE_AES_GENERATOR 1

using namespace CryptoPP;
using namespace Weak1;

const char * hexChars = "0123456789ABCDEF";

SHA1 * g_sha = NULL ;

#ifdef __cplusplus
extern "C" { 
#endif

unsigned int GetDigestSize(unsigned int algorithms)
{
    switch(algorithms)
        {
            case algo_md2:
                return MD2::DIGESTSIZE ;
            break;
            case algo_md4:
                return MD4::DIGESTSIZE ;
            break;
            case algo_md5:
                return MD5::DIGESTSIZE ;
            break;
            /*case algo_panama:
                if(length==Panama::DIGESTSIZE)
                {
                    DebugFormat("PANAMA Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Panama::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Panama::DIGESTSIZE ;
            break;*/
            /*case algo_des:
                if(length==DES::DIGESTSIZE)
                {
                    DebugFormat("DES Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,DES::DIGESTSIZE);
                    return NULL;
                }
                maxLength = DES::DIGESTSIZE ;
            break;*/
            /*case algo_arc4:
                if(length==ARC4::DIGESTSIZE)
                {
                    DebugFormat("ARC4 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,ARC4::DIGESTSIZE);
                    return NULL;
                }
                maxLength = ARC4::DIGESTSIZE ;
            break;*/
            /*case algo_seal:
                if(length==SEAL::DIGESTSIZE)
                {
                    DebugFormat("SEAL Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SEAL::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SEAL::DIGESTSIZE ;
            break;*/
            case algo_sha1:
                return  SHA1::DIGESTSIZE ;
            break;
            case algo_sha224:
                return SHA224::DIGESTSIZE ;
            break;
            case algo_sha256:
                return SHA256::DIGESTSIZE ;
            break;
            case algo_sha384:
                return SHA384::DIGESTSIZE ;
            break;
            case algo_sha512:
                return SHA512::DIGESTSIZE ;
            break;
            case algo_sha3_224:
                return SHA3_224::DIGESTSIZE ;
            break;
            case algo_sha3_256:
                return SHA3_256::DIGESTSIZE ;
            break;
            case algo_sha3_384:
                return SHA3_384::DIGESTSIZE ;
            break;
            case algo_sha3_512:
                return SHA3_512::DIGESTSIZE ;
            break;
            case algo_ripemd_128:
                return RIPEMD128::DIGESTSIZE ;
            break;
            case algo_ripemd_160:
                return RIPEMD160::DIGESTSIZE ;
            break;
            case algo_ripemd_256:
                return RIPEMD256::DIGESTSIZE ;
            break;
            case algo_ripemd_320:
                return RIPEMD320::DIGESTSIZE ;
            break;
            case algo_blake2b:
                return BLAKE2b::DIGESTSIZE;
            break;
            case algo_blake2s:
                return BLAKE2s::DIGESTSIZE;
            break;
            case algo_tiger:
                return Tiger::DIGESTSIZE;
            break;
            case algo_shake_128:
                return SHAKE128::DIGESTSIZE;
            break;
            case algo_shake_256:
                return SHAKE256::DIGESTSIZE;
            break;
            case algo_sip_hash64:
                return SipHash<2,4,false>::DIGESTSIZE;
            break;
            case algo_sip_hash128:
                return SipHash<4,8,true>::DIGESTSIZE;
            break;
            case algo_lsh_224:
                return LSH224::DIGESTSIZE;
            break;
            case algo_lsh_256:
                return LSH256::DIGESTSIZE;
            break;
            case algo_lsh_384:
                return LSH384::DIGESTSIZE;
            break;
            case algo_lsh_512:
                return LSH512::DIGESTSIZE;
            break;
            case algo_sm3:
                return SM3::DIGESTSIZE;
            break;
            case algo_whirlpool:
                return Whirlpool::DIGESTSIZE;
            break;
            default :
                return 0;
        }
}

const char * DoMd2(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(MD2::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,MD2::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            MD2().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", MD2::DIGESTSIZE);
            result= ToHex(lpBuffer,MD2::DIGESTSIZE,algo_md2);
            if(result!=NULL)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(MD2::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlen(result),(MD2::DIGESTSIZE*2), result );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoMd4(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(MD4::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,MD4::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            MD4().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", MD4::DIGESTSIZE);
            result= ToHex(lpBuffer,MD4::DIGESTSIZE,algo_md4);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(MD4::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(MD4::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoMd5(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(MD5::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,MD5::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            MD5().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",MD5::DIGESTSIZE);
            result= ToHex(lpBuffer,MD5::DIGESTSIZE,algo_md5);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(MD5::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(MD5::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoPanama(const char * message)
{
    /*char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(Panama::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("Buffer allocated\r\n");
            SHA1().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", strlen(lpBuffer));
            if(strlen(lpBuffer)!=Panama::DIGESTSIZE)
            {
                DebugFormat("Digest is not correct size: %i - %i",strlen(lpBuffer), Panama::DIGESTSIZE );
                return NULL;
            }
            result= ToHex(lpBuffer,algo_panama);
            if(strlen(result)!=Panama::DIGESTSIZE*2)
            {
                DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),Panama::DIGESTSIZE*2 );
                return NULL;
            }
            OutputDebugStringA("Processed ToHex\r\n");
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }*/
	return NULL;
}

const char * DoDES(const char * message)
{
    /*char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(DES::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("Buffer allocated\r\n");
            SHA1().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", strlen(lpBuffer));
            if(strlen(lpBuffer)!=DES::DIGESTSIZE)
            {
                DebugFormat("Digest is not correct size: %i - %i",strlen(lpBuffer), DES::DIGESTSIZE );
                return NULL;
            }
            result= ToHex(lpBuffer,algo_des);
            if(strlen(result)!=DES::DIGESTSIZE*2)
            {
                DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),DES::DIGESTSIZE*2 );
                return NULL;
            }
            OutputDebugStringA("Processed ToHex\r\n");
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }*/
	return NULL;
}

const char * DoArc4(const char * message)
{
    /*char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(ARC4::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("Buffer allocated\r\n");
            SHA1().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", strlen(lpBuffer));
            if(strlen(lpBuffer)!=ARC4::DIGESTSIZE)
            {
                DebugFormat("Digest is not correct size: %i - %i",strlen(lpBuffer), ARC4::DIGESTSIZE );
                return NULL;
            }
            result= ToHex(lpBuffer,algo_arc4);
            if(strlen(result)!=ARC4::DIGESTSIZE*2)
            {
                DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),ARC4::DIGESTSIZE*2 );
                return NULL;
            }
            OutputDebugStringA("Processed ToHex\r\n");
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }*/
	return NULL;
}

const char * DoSeal(const char * message)
{
    /*char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SEAL::DIGESTSIZE);
        if(lpBuffer)
        {
            OutputDebugStringA("Buffer allocated\r\n");
            SHA1().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", strlen(lpBuffer));
            if(strlen(lpBuffer)!=SEAL::DIGESTSIZE)
            {
                DebugFormat("Digest is not correct size: %i - %i",strlen(lpBuffer), SEAL::DIGESTSIZE );
                return NULL;
            }
            result= ToHex(lpBuffer,algo_seal);
            if(strlen(result)!=SEAL::DIGESTSIZE*2)
            {
                DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),SEAL::DIGESTSIZE*2 );
                return NULL;
            }
            OutputDebugStringA("Processed ToHex\r\n");
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }*/
	return NULL;
}

const char * DoSha(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA1::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA1::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA1().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA1::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA1::DIGESTSIZE,algo_sha1);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA1::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA1::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSha224(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA224::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA224::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA224().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA224::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA224::DIGESTSIZE,algo_sha224);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA224::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA224::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}


const char * DoSha256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA256::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA256::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA256::DIGESTSIZE,algo_sha256);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA256::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSha384(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA384::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA384::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA384().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA384::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA384::DIGESTSIZE,algo_sha384);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA384::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA384::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSha512(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA512::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA512::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA512().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA512::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA512::DIGESTSIZE,algo_sha512);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA512::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA512::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSha3_224(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA3_224::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_224::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA3_224().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_224::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_224::DIGESTSIZE,algo_sha3_224);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_224::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_224::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}


const char * DoSha3_256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA3_256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_256::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA3_256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_256::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_256::DIGESTSIZE,algo_sha3_256);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_256::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSha3_384(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA3_384::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_384::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA3_384().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_384::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_384::DIGESTSIZE,algo_sha3_384);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_384::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_384::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSha3_512(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHA3_512::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_512::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHA3_512().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_512::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_512::DIGESTSIZE,algo_sha3_512);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_512::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_512::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoRipeMD128(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD128::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD128::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            RIPEMD128().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD128::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD128::DIGESTSIZE,algo_ripemd_128);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD128::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD128::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoRipeMD160(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD160::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD160::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            RIPEMD160().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD160::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD160::DIGESTSIZE,algo_ripemd_160);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD160::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD160::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoRipeMD256(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD256::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            RIPEMD256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD256::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD256::DIGESTSIZE,algo_ripemd_256);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD256::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoRipeMD320(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD320::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD320::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            RIPEMD320().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD320::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD320::DIGESTSIZE,algo_ripemd_320);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD320::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD320::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoBlake2b(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(BLAKE2b::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,BLAKE2b::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            BLAKE2b().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",BLAKE2b::DIGESTSIZE);
            result= ToHex(lpBuffer,BLAKE2b::DIGESTSIZE,algo_blake2b);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(BLAKE2b::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(BLAKE2b::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoBlake2s(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(BLAKE2s::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,BLAKE2s::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            BLAKE2s().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",BLAKE2s::DIGESTSIZE);
            result= ToHex(lpBuffer,BLAKE2s::DIGESTSIZE,algo_blake2s);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(BLAKE2s::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(BLAKE2s::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoTiger(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(Tiger::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,Tiger::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            Tiger().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",Tiger::DIGESTSIZE);
            result= ToHex(lpBuffer,Tiger::DIGESTSIZE,algo_tiger);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(Tiger::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(Tiger::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoShake128(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHAKE128::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHAKE128::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHAKE128().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHAKE128::DIGESTSIZE);
            result= ToHex(lpBuffer,SHAKE128::DIGESTSIZE,algo_shake_128);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHAKE128::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHAKE128::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoShake256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SHAKE256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHAKE256::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SHAKE256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHAKE256::DIGESTSIZE);
            result= ToHex(lpBuffer,SHAKE256::DIGESTSIZE,algo_shake_256);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SHAKE256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHAKE256::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSipHash64(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SipHash<2,4,false>::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SipHash<2,4,false>::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SipHash<2,4,false>().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SipHash<2,4,false>::DIGESTSIZE);
            result= ToHex(lpBuffer,SipHash<2,4,false>::DIGESTSIZE,algo_sip_hash64);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SipHash<2,4,false>::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SipHash<2,4,false>::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSipHash128(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SipHash<4,8,true>::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SipHash<4,8,true>::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SipHash<4,8,true>().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SipHash<4,8,true>::DIGESTSIZE);
            result= ToHex(lpBuffer,SipHash<4,8,true>::DIGESTSIZE,algo_sip_hash128);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SipHash<4,8,true>::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SipHash<4,8,true>::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoLSH224(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(LSH224::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH224::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            LSH224().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH224::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH224::DIGESTSIZE,algo_lsh_224);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(LSH224::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH224::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoLSH256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(LSH256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH256::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            LSH256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH256::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH256::DIGESTSIZE,algo_lsh_256);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(LSH256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH256::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoLSH384(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(LSH384::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH384::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            LSH384().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH384::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH384::DIGESTSIZE,algo_lsh_384);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(LSH384::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH384::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoLSH512(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(LSH512::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH512::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            LSH512().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH512::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH512::DIGESTSIZE,algo_lsh_512);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(LSH512::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH512::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoSM3(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(SM3::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SM3::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            SM3().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SM3::DIGESTSIZE);
            result= ToHex(lpBuffer,SM3::DIGESTSIZE,algo_sm3);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(SM3::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SM3::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

const char * DoWhirlpool(const char * message)
{
char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        OutputDebugStringA("Message passed in is:");
        OutputDebugStringA(message);
        OutputDebugStringA("\r\n");
        lpBuffer = (char * ) malloc(Whirlpool::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,Whirlpool::DIGESTSIZE);
            OutputDebugStringA("Buffer allocated\r\n");
            Whirlpool().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",Whirlpool::DIGESTSIZE);
            result= ToHex(lpBuffer,Whirlpool::DIGESTSIZE,algo_whirlpool);
            if(result)
            {
                OutputDebugStringA("Processed ToHex\r\n");
                if(strlen(result)!=(Whirlpool::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(Whirlpool::DIGESTSIZE*2) );
                    return NULL;
                }
            }
            else
            {
                OutputDebugStringA("Failed to convert to hex\r\n");
            }
            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            OutputDebugStringA("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        OutputDebugStringA("Message passed in is NULL\r\n");
    }
	return NULL;
}

void InitSha()
{
    if(g_sha)
    {
        delete g_sha;
    }
    g_sha = new SHA1();
}

void DoShaUpdate(const char * message, unsigned int length)
{
    if(g_sha)
    {
        g_sha->Update((const CryptoPP::byte *)message, length);
    }
}

const char * DoShaFinal(const char * message, unsigned int length)
{   
    std::string digest; 
    if(g_sha)
    {
        g_sha->Update((const CryptoPP::byte *)message, length);
        g_sha->Final((byte*)&digest[0]);
        return ToHex(digest.c_str(),SHA1::DIGESTSIZE,algo_sha1);
    }
    return NULL;
}



void UninitSha()
{
    if(g_sha)
    {
        delete g_sha;
        g_sha = NULL;
    }
}

const char * ToHex(const char * value, unsigned int length, unsigned int algorithms)
{
    char * hexValue = NULL;
    char theChar =0;
    unsigned int maxLength = 0 ;
    unsigned int index=0;
    unsigned int valueIndex=0;
    if ( value )
    {
        switch(algorithms)
        {
            case algo_md2:
                if(length!=MD2::DIGESTSIZE)
                {
                    DebugFormat("MD2 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,MD2::DIGESTSIZE);
                    return NULL;
                }
                maxLength = MD2::DIGESTSIZE*2 ;
            break;
            case algo_md4:
                if(length!=MD4::DIGESTSIZE)
                {
                    DebugFormat("MD4 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,MD4::DIGESTSIZE);
                    return NULL;
                }
                maxLength = MD4::DIGESTSIZE*2 ;
            break;
            case algo_md5:
                if(length!=MD5::DIGESTSIZE)
                {
                    DebugFormat("MD5 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,MD5::DIGESTSIZE);
                    return NULL;
                }
                maxLength = MD5::DIGESTSIZE*2 ;
            break;
            /*case algo_panama:
                if(length==Panama::DIGESTSIZE)
                {
                    DebugFormat("PANAMA Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Panama::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Panama::DIGESTSIZE ;
            break;*/
            /*case algo_des:
                if(length==DES::DIGESTSIZE)
                {
                    DebugFormat("DES Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,DES::DIGESTSIZE);
                    return NULL;
                }
                maxLength = DES::DIGESTSIZE ;
            break;*/
            /*case algo_arc4:
                if(length==ARC4::DIGESTSIZE)
                {
                    DebugFormat("ARC4 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,ARC4::DIGESTSIZE);
                    return NULL;
                }
                maxLength = ARC4::DIGESTSIZE ;
            break;*/
            /*case algo_seal:
                if(length==SEAL::DIGESTSIZE)
                {
                    DebugFormat("SEAL Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SEAL::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SEAL::DIGESTSIZE ;
            break;*/
            case algo_sha1:
                if(length!=SHA1::DIGESTSIZE)
                {
                    DebugFormat("SHA1 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA1::DIGESTSIZE*2 ;
            break;
            case algo_sha224:
                if(length!=SHA224::DIGESTSIZE)
                {
                    DebugFormat("SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA224::DIGESTSIZE*2 ;
            break;
            case algo_sha256:
                if(length!=SHA256::DIGESTSIZE)
                {
                    DebugFormat("SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE*2 ;
            break;
            case algo_sha384:
                if(length!=SHA384::DIGESTSIZE)
                {
                    DebugFormat("SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA384::DIGESTSIZE*2 ;
            break;
            case algo_sha512:
                if(length!=SHA512::DIGESTSIZE)
                {
                    DebugFormat("SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA512::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA512::DIGESTSIZE*2 ;
            break;
            case algo_sha3_224:
                if(length!=SHA224::DIGESTSIZE)
                {
                    DebugFormat("SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA224::DIGESTSIZE*2 ;
            break;
            case algo_sha3_256:
                if(length!=SHA256::DIGESTSIZE)
                {
                    DebugFormat("SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE*2 ;
            break;
            case algo_sha3_384:
                if(length!=SHA384::DIGESTSIZE)
                {
                    DebugFormat("SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA384::DIGESTSIZE*2 ;
            break;
            case algo_sha3_512:
                if(length!=SHA512::DIGESTSIZE)
                {
                    DebugFormat("SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA512::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA512::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_128:
                if(length!=RIPEMD128::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD128 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD128::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD128::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_160:
                if(length!=RIPEMD160::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD160 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD160::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD160::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_256:
                if(length!=RIPEMD256::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD256::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_320:
                if(length!=RIPEMD320::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD320 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD320::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD320::DIGESTSIZE*2 ;
            break;
            case algo_blake2b:
                if(length!=BLAKE2b::DIGESTSIZE)
                {
                    DebugFormat("BLAKE2b Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,BLAKE2b::DIGESTSIZE);
                    return NULL;
                }
                maxLength = BLAKE2b::DIGESTSIZE*2 ;
            break;
            case algo_blake2s:
                if(length!=BLAKE2s::DIGESTSIZE)
                {
                    DebugFormat("BLAKE2s Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,BLAKE2s::DIGESTSIZE);
                    return NULL;
                }
                maxLength = BLAKE2s::DIGESTSIZE*2 ;
            break;
            case algo_tiger:
                if(length!=Tiger::DIGESTSIZE)
                {
                    DebugFormat("Tiger Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Tiger::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Tiger::DIGESTSIZE*2 ;
            break;
            case algo_shake_128:
                if(length!=SHAKE128::DIGESTSIZE)
                {
                    DebugFormat("SHAKE128 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHAKE128::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHAKE128::DIGESTSIZE*2 ;
            break;
            case algo_shake_256:
                if(length!=SHAKE256::DIGESTSIZE)
                {
                    DebugFormat("SHAKE256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHAKE256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHAKE256::DIGESTSIZE*2 ;
            break;
            case algo_sip_hash64:
                if(length!=SipHash<2,4,false>::DIGESTSIZE)
                {
                    DebugFormat("SipHash64 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SipHash<2,4,false>::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SipHash<2,4,false>::DIGESTSIZE*2 ;
            break;
            case algo_sip_hash128:
                if(length!=SipHash<4,8,true>::DIGESTSIZE)
                {
                    DebugFormat("SipHash128 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SipHash<4,8,true>::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SipHash<4,8,true>::DIGESTSIZE*2 ;
            break;
            case algo_lsh_224:
                if(length!=LSH224::DIGESTSIZE)
                {
                    DebugFormat("LSH224 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH224::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH224::DIGESTSIZE*2 ;
            break;
            case algo_lsh_256:
                if(length!=LSH256::DIGESTSIZE)
                {
                    DebugFormat("LSH256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH256::DIGESTSIZE*2 ;
            break;
            case algo_lsh_384:
                if(length!=LSH384::DIGESTSIZE)
                {
                    DebugFormat("LSH384 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH384::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH384::DIGESTSIZE*2 ;
            break;
            case algo_lsh_512:
                if(length!=LSH512::DIGESTSIZE)
                {
                    DebugFormat("LSH512 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH512::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH512::DIGESTSIZE*2 ;
            break;
            case algo_sm3:
                if(length!=SM3::DIGESTSIZE)
                {
                    DebugFormat("SM3 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SM3::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SM3::DIGESTSIZE*2 ;
            break;
            case algo_whirlpool:
                if(length!=Whirlpool::DIGESTSIZE)
                {
                    DebugFormat("Whirlpool Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Whirlpool::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Whirlpool::DIGESTSIZE*2 ;
            break;
            default :
                return NULL;
        }
        hexValue = ( char * ) malloc((length*2)+1);
        if(hexValue)
        {
            for(index = 0 ; index< length ;index++)
            {
                theChar = (((value[index]&0xF0)>>4)&0x0F);
                hexValue[valueIndex] = hexChars[theChar];
                if(valueIndex>(maxLength))
                {
                       
                    break;
                }
                DebugFormat("Index:%i ValueIndex:%i Initial: %x Char: %i Value: %i\r\n",index,valueIndex,value[index],theChar, hexValue[valueIndex]);
                valueIndex++;
                theChar = ((value[index])&0x0F);
                hexValue[valueIndex] = hexChars[theChar];
                if(valueIndex>(maxLength))
                {
                    
                    break;
                }
                DebugFormat("Index:%i ValueIndex:%i Initial: %x Char: %i Value: %i\r\n",index,valueIndex,value[index],theChar, hexValue[valueIndex]);
                valueIndex++;
            }
            hexValue[maxLength]='\0';
            if(SelfCheckToHex(hexValue,maxLength,algorithms)!=1)
            {
                DebugFormat("hexValue Failed to SelfCheck\r\n");
                return NULL;
            }
        }
        else
        {
            DebugFormat("hexValue Failed to allocated\r\n");
            return NULL;
        }
    }
    else
    {
        DebugFormat("Value is NULL\r\n");
        return NULL;
    }
    return hexValue;
}

unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) 
{
    unsigned int index=0;
    unsigned int maxLength=0;
    if ( value )
    {
        switch(algorithm)
        {
            case algo_md2:
                if(length!=MD2::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck MD2 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,MD2::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = MD2::DIGESTSIZE *2;
            break;
            case algo_md4:
                if(length!=MD4::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck MD4 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,MD4::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = MD4::DIGESTSIZE*2 ;
            break;
            case algo_md5:
                if(length!=MD5::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck MD5 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,MD5::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = MD5::DIGESTSIZE*2 ;
            break;
            /*case algo_panama:
                if(length==Panama::DIGESTSIZE)
                {
                    DebugFormat("PANAMA Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Panama::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Panama::DIGESTSIZE ;
            break;*/
            /*case algo_des:
                if(length==DES::DIGESTSIZE)
                {
                    DebugFormat("DES Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,DES::DIGESTSIZE);
                    return NULL;
                }
                maxLength = DES::DIGESTSIZE ;
            break;*/
            /*case algo_arc4:
                if(length==ARC4::DIGESTSIZE)
                {
                    DebugFormat("ARC4 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,ARC4::DIGESTSIZE);
                    return NULL;
                }
                maxLength = ARC4::DIGESTSIZE ;
            break;*/
            /*case algo_seal:
                if(length==SEAL::DIGESTSIZE)
                {
                    DebugFormat("SEAL Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SEAL::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SEAL::DIGESTSIZE ;
            break;*/
            case algo_sha1:
                if(length!=SHA1::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA1 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA1::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA1::DIGESTSIZE *2;
            break;
            case algo_sha224:
                if(length!=SHA224::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA224::DIGESTSIZE*2;
            break;
            case algo_sha256:
                if(length!=SHA256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE*2;
            break;
            case algo_sha384:
                if(length!=SHA384::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA384::DIGESTSIZE*2;
            break;
            case algo_sha512:
                if(length!=SHA512::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA512::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA512::DIGESTSIZE*2 ;
            break;
            case algo_sha3_224:
                if(length!=SHA3_224::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_224 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_224::DIGESTSIZE*2;
            break;
            case algo_sha3_256:
                if(length!=SHA3_256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_256::DIGESTSIZE*2;
            break;
            case algo_sha3_384:
                if(length!=SHA3_384::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_384 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_384::DIGESTSIZE*2;
            break;
            case algo_sha3_512:
                if(length!=SHA3_512::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_512 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA512::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_512::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_128:
                if(length!=RIPEMD128::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD128 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD128::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD128::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_160:
                if(length!=RIPEMD160::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD160 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD160::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD160::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_256:
                if(length!=RIPEMD256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD256::DIGESTSIZE*2 ;
            break;
            case algo_ripemd_320:
                if(length!=RIPEMD320::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD320 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD320::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD320::DIGESTSIZE*2 ;
            break;
            case algo_blake2b:
                if(length!=BLAKE2b::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck BLAKE2b Algorithm Length does not match actual length: [%i] [%i]\r\n",length,BLAKE2b::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = BLAKE2b::DIGESTSIZE*2 ;
            break;
            case algo_blake2s:
                if(length!=BLAKE2s::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck BLAKE2s Algorithm Length does not match actual length: [%i] [%i]\r\n",length,BLAKE2s::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = BLAKE2s::DIGESTSIZE*2 ;
            break;
            case algo_tiger:
                if(length!=Tiger::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck Tiger Algorithm Length does not match actual length: [%i] [%i]\r\n",length,Tiger::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = Tiger::DIGESTSIZE*2 ;
            break;
            case algo_shake_128:
                if(length!=SHAKE128::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHAKE128 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHAKE128::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHAKE128::DIGESTSIZE*2 ;
            break;
            case algo_shake_256:
                if(length!=SHAKE256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHAKE256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHAKE256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHAKE256::DIGESTSIZE*2 ;
            break;
            case algo_sip_hash64:
                if(length!=SipHash<2,4,false>::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SipHash64 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SipHash<2,4,false>::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SipHash<2,4,false>::DIGESTSIZE*2 ;
            break;
            case algo_sip_hash128:
                if(length!=SipHash<4,8,true>::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SipHash128 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SipHash<4,8,true>::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SipHash<4,8,true>::DIGESTSIZE*2 ;
            break;
            case algo_lsh_224:
                if(length!=LSH224::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH224 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH224::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH224::DIGESTSIZE*2 ;
            break;
            case algo_lsh_256:
                if(length!=LSH256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH256 Tiger Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH256::DIGESTSIZE*2 ;
            break;
            case algo_lsh_384:
                if(length!=LSH384::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH384 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH384::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH384::DIGESTSIZE*2 ;
            break;
            case algo_lsh_512:
                if(length!=LSH512::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH512 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH512::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH512::DIGESTSIZE*2 ;
            break;
            case algo_sm3:
                if(length!=SM3::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SM3 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SM3::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SM3::DIGESTSIZE*2 ;
            break;
            case algo_whirlpool:
                if(length!=Whirlpool::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck Whirlpool Algorithm Length does not match actual length: [%i] [%i]\r\n",length,Whirlpool::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = Whirlpool::DIGESTSIZE*2 ;
            break;
            
            default :
                DebugFormat("Invalid Algorithm: [%i] [%i]\r\n",algorithm);
                return 0;
        }
        for(index=0;index<maxLength;index++)
        {
            if(
                (*value>='0' && *value<='9')||
                (*value>='a' && *value<='f')||
                (*value>='A' && *value<='F')
            )
            {
                continue;
            }
            else
            {
                DebugFormat("Index: %i Value: %c\r\n", index, value);
                return 0;
            }
        }
        return 1;
    }
    else
    {
        DebugFormat("Value is NULL\r\n");
    }
    return 0;
}


void FreeCryptoResult(const void * object)
{
    if(object!=NULL)
    {
        free((void*)object);
    }
}

void DebugFormat( const char * format, ...)
{
    std::va_list args;
    std::stringstream outputStream;
    va_start(args, format);
 
    for (const char* p = format; *p != '\0'; ++p)
    {
        switch (*p)
        {
        case '%':
            switch (*++p) // read format symbol
            {
                case 'i':
                case 'd':
                    outputStream << va_arg(args, int);
                    continue;
                case 'f':
                    outputStream << va_arg(args, double);
                    continue;
                case 's':
                    outputStream << va_arg(args, const char*);
                    continue;
                case 'c':
                    outputStream << static_cast<char>(va_arg(args, int));
                    continue;
                case '%':
                    outputStream << '%';
                    continue;
                case 'x':
                    outputStream << std::hex << va_arg(args, int);
                    continue;
                case 'o':
                    outputStream << std::oct << va_arg(args, int);
                    continue;
                /* ...more cases... */
            }
            break; // format error...
        case '\n':
            outputStream << '\n';
            continue;
        case '\t':
            outputStream << '\t';
            continue;
        case ' ':
            outputStream << ' ';
        default:
            outputStream<<*p;
        }
    }
    va_end(args);
    OutputDebugStringA(outputStream.str().c_str());
}

#ifdef __cplusplus
} 
#endif