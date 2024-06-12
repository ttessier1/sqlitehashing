#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#define __WINDOWS_BCRYPT__

#include "crypto_hashing.h"

#include <cryptlib.h>
#include <filters.h>

//#if defined(__MD2__) || (defined __ALL__)
#include <md2.h>
//#endif

#if defined(__MD4__) || (defined __ALL__)
#include <md4.h>
#endif

#if defined(__MD5__) || (defined __ALL__)
#include <md5.h>
#endif

#if defined(__SHA1__) ||defined(__SHA224__) ||defined(__SHA256__) || defined(__SHA384__) ||defined(__SHA512__) ||(defined __ALL__)
#include <sha.h>
#endif

#if defined(__SHA3224__) ||defined(__SHA3256__) ||defined(__SHA3384__) || defined(__SHA3512__) || (defined __ALL__)
#include <sha3.h>
#endif

#if defined(__MD128__) ||defined(__MD160__) ||defined(__MD256__) ||defined(__MD256__) || defined(__ALL__)
#include <ripemd.h>
#endif

#if defined(__BLAKE2B__) ||defined(__BLAKE2S__)|| defined(__ALL__)
#include <blake2.h>
#endif

#if defined(__TIGER__) || defined(__ALL__)
#include <tiger.h>
#endif

#if defined(__SHAKE128__)||defined(__SHAKE256__)|| defined(__ALL__)
#include <shake.h>
#endif

#if defined(__SIPHASH64__)||defined(__SIPHASH128__)|| defined(__ALL__)
#include <siphash.h>
#endif

#if defined(__LSH224__) ||defined(__LSH256__)||defined(__LSH384__)||defined(__LSH512__)|| defined(__ALL__)
#include <lsh.h>
#endif

#if defined(__SM3__) || defined(__ALL__)
#include <sm3.h>
#endif

#if defined(__WHIRLPOOL__) || defined(__ALL__)
#include <whrlpool.h>
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

// If CRYPTOPP_USE_AES_GENERATOR is 1 then AES/OFB based is used.
// Otherwise the OS random number generator is used.
#define CRYPTOPP_USE_AES_GENERATOR 1

using namespace CryptoPP;

//#if defined(__MD2__) ||  defined(__MD4__) ||  defined(__MD5__) ||  (defined __ALL__)

using namespace Weak1;

//#endif


//SHA1 * g_sha = NULL ;

#ifdef __cplusplus
extern "C" { 
#endif


//#if defined ( __MD2__ ) || defined(__ALL__)

const char * DoMd2(const char * message)
{
    char * lpBuffer = NULL;
    const char * result = NULL;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(MD2::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,MD2::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
#if defined __CRYPTOCPP__
            MD2().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", MD2::DIGESTSIZE);
            result= ToHex(lpBuffer,MD2::DIGESTSIZE,algo_md2);
            if(result!=NULL)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(MD2::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i %s\r\n", strlen(result),(MD2::DIGESTSIZE*2), result );
                    return NULL;
                }
            }
            else
            {
                DebugMessage("Failed to convert to hex\r\n");
            }
#elsif __WINDOWS_BCRYPT__
    BOOL bContinue = FALSE;
    BOOL returnCode = FALSE;
    DWORD result = 0;
    ULONG size_required = 0;
    BCRYPT_ALG_HANDLE algorithmHandle;
    BCRYPT_HASH_HANDLE hashHandle;
    uint8_t generatedHash[326];
    uint8_t hexGeneratedHash[65];
    DWORD bytesRead = 0;
    uint32_t index = 0;
    unsigned char buffer[BUFFER_SIZE];
    DWORD objectsize = 0;
    HANDLE hFileHandle = INVALID_HANDLE_VALUE;
    result = BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_MD2_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_HASH_REUSABLE_FLAG);
    if (BCRYPT_SUCCESS(result))
    {
        result = BCryptCreateHash(algorithmHandle, &hashHandle, generatedHash, 326, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
        if (STATUS_BUFFER_TOO_SMALL == result)
        {
            result = BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectsize, 4, &size_required, 0);
            if ( result == 0)
            {
                
                
            }
            else
            {
                fprintf(stderr, "Failed to get object property: %d\r\n", result);
            }
            fprintf(stderr, "Failed to open create sha256 hash: BUFFER TOO SMALL\r\n");
        }
        if (BCRYPT_SUCCESS(result))
        {
            hFileHandle = CreateFileA(pszFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hFileHandle != INVALID_HANDLE_VALUE)
            {
                bContinue = TRUE;
                while (bContinue)
                {
                    if (ReadFile(hFileHandle, buffer, BUFFER_SIZE, &bytesRead, NULL))
                    {
                        if (bytesRead == BUFFER_SIZE)
                        {
                            if (BCRYPT_SUCCESS(BCryptHashData(hashHandle, buffer, BUFFER_SIZE, 0)))
                            {

                            }
                            else
                            {
                                fprintf(stderr, "Failed to perform hash round\r\n");
                                bContinue = FALSE;
                            }
                        }
                        else
                        {
                            if (BCRYPT_SUCCESS(BCryptHashData(hashHandle, buffer, bytesRead, 0)))
                            {
                                if (BCRYPT_SUCCESS(BCryptFinishHash(hashHandle, generatedHash, 32, 0)))
                                {
                                    bContinue = FALSE;
                                    returnCode = TRUE;
                                }
                                else
                                {
                                    bContinue = FALSE;
                                    returnCode = FALSE;
                                    fprintf(stderr, "Failed to perform FINAL hash round\r\n");
                                }
                            }
                            else
                            {
                                fprintf(stderr, "Failed to perform hash round\r\n");
                                bContinue = FALSE;
                            }

                        }
                    }
                    else
                    {
                        bContinue = FALSE;
                        fprintf(stderr, "FAiled to read the file: %d\r\n", GetLastError());
                    }
                }
                CloseHandle(hFileHandle);
                if (returnCode)
                {
                    for (int i = 0; i < 32; i++)
                    {
                        hexGeneratedHash[index] = hexChars[(generatedHash[i] & 0xF0) >> 4];
                        index++;
                        hexGeneratedHash[index] = hexChars[generatedHash[i] & 0xF];
                        index++;
                        hexGeneratedHash[index] = '\0';
                    }
                    if (_strcmpi((char*)hexGeneratedHash, (char*)hash) == 0)
                    {
                        returnCode = TRUE;
                    }
                    else
                    {
                        returnCode = FALSE;
                    }
                }

            }
            else
            {

                fprintf(stderr, "Failed to open file: %s for hash verification\r\n", pszFileName);
            }
            BCryptDestroyHash(hashHandle);

        }
        else
        {
            if (STATUS_BUFFER_TOO_SMALL == result)
            {
                result = BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectsize, 4, &size_required, 0);
                if (result == STATUS_BUFFER_TOO_SMALL || result == 0)
                {
                    fprintf(stderr, "Size: %d", objectsize);
                }
                else
                {
                    fprintf(stderr, "Failed to get object property: %d\r\n", result);
                }
                fprintf(stderr, "Failed to open create sha256 hash: BUFFER TOO SMALL\r\n");
            }
            else
            {
                fprintf(stderr, "Failed to open create sha256 hash: %d\r\n", result);
            }

        }
        BCryptCloseAlgorithmProvider(algorithmHandle, 0);

    }
    else
    {
        fprintf(stderr, "Failed to open a suitable crypto provider for sha256: %d\r\n", result);
    }
    return returnCode;
}
#endif

            free(lpBuffer);
            lpBuffer = NULL;
            return result;
        }
        else
        {
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}


//#endif

#if defined ( __MD4__ ) || defined(__ALL__)

const char * DoMd4(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(MD4::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,MD4::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            MD4().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n", MD4::DIGESTSIZE);
            result= ToHex(lpBuffer,MD4::DIGESTSIZE,algo_md4);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(MD4::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(MD4::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __MD5__ ) || defined(__ALL__)

const char * DoMd5(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(MD5::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,MD5::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            MD5().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",MD5::DIGESTSIZE);
            result= ToHex(lpBuffer,MD5::DIGESTSIZE,algo_md5);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(MD5::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(MD5::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA1__ ) || defined(__ALL__)

const char * DoSha1(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA1::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA1::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA1().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA1::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA1::DIGESTSIZE,algo_sha1);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA1::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA1::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA224__ ) || defined(__ALL__)

const char * DoSha224(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA224::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA224::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA224().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA224::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA224::DIGESTSIZE,algo_sha224);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA224::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA224::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA256__ ) || defined(__ALL__)

const char * DoSha256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA256::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA256::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA256::DIGESTSIZE,algo_sha256);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA256::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA384__ ) || defined(__ALL__)

const char * DoSha384(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA384::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA384::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA384().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA384::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA384::DIGESTSIZE,algo_sha384);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA384::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA384::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA512__ ) || defined(__ALL__)

const char * DoSha512(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA512::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA512::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA512().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA512::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA512::DIGESTSIZE,algo_sha512);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA512::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA512::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA3224__ ) || defined(__ALL__)

const char * DoSha3_224(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA3_224::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_224::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA3_224().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_224::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_224::DIGESTSIZE,algo_sha3_224);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_224::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_224::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA3256__ ) || defined(__ALL__)

const char * DoSha3_256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA3_256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_256::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA3_256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_256::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_256::DIGESTSIZE,algo_sha3_256);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_256::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA3384__ ) || defined(__ALL__)

const char * DoSha3_384(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA3_384::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_384::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA3_384().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_384::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_384::DIGESTSIZE,algo_sha3_384);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_384::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_384::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHA3512__ ) || defined(__ALL__)

const char * DoSha3_512(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHA3_512::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHA3_512::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHA3_512().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHA3_512::DIGESTSIZE);
            result= ToHex(lpBuffer,SHA3_512::DIGESTSIZE,algo_sha3_512);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHA3_512::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHA3_512::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __MD128__ ) || defined(__ALL__)

const char * DoRipeMD128(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD128::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD128::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            RIPEMD128().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD128::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD128::DIGESTSIZE,algo_ripemd_128);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD128::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD128::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __MD160__ ) || defined(__ALL__)

const char * DoRipeMD160(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD160::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD160::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            RIPEMD160().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD160::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD160::DIGESTSIZE,algo_ripemd_160);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD160::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD160::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __MD256__ ) || defined(__ALL__)

const char * DoRipeMD256(const char * message)
{
     char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD256::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            RIPEMD256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD256::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD256::DIGESTSIZE,algo_ripemd_256);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD256::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __MD320__ ) || defined(__ALL__)

const char * DoRipeMD320(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(RIPEMD320::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,RIPEMD320::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            RIPEMD320().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",RIPEMD320::DIGESTSIZE);
            result= ToHex(lpBuffer,RIPEMD320::DIGESTSIZE,algo_ripemd_320);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(RIPEMD320::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(RIPEMD320::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __BLAKE2B__ ) || defined(__ALL__)

const char * DoBlake2b(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(BLAKE2b::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,BLAKE2b::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            BLAKE2b().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
            DebugFormat("Processed Message to Buffer Length: %i\r\n",BLAKE2b::DIGESTSIZE);
            result= ToHex(lpBuffer,BLAKE2b::DIGESTSIZE,algo_blake2b);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(BLAKE2b::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(BLAKE2b::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __BLAKE2S__ ) || defined(__ALL__)

const char * DoBlake2s(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(BLAKE2s::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,BLAKE2s::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            BLAKE2s().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",BLAKE2s::DIGESTSIZE);
            result= ToHex(lpBuffer,BLAKE2s::DIGESTSIZE,algo_blake2s);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(BLAKE2s::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(BLAKE2s::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __TIGER__ ) || defined(__ALL__)

const char * DoTiger(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(Tiger::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,Tiger::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            Tiger().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",Tiger::DIGESTSIZE);
            result= ToHex(lpBuffer,Tiger::DIGESTSIZE,algo_tiger);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(Tiger::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(Tiger::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHAKE128__ ) || defined(__ALL__)

const char * DoShake128(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHAKE128::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHAKE128::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHAKE128().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHAKE128::DIGESTSIZE);
            result= ToHex(lpBuffer,SHAKE128::DIGESTSIZE,algo_shake_128);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHAKE128::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHAKE128::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SHAKE256__ ) || defined(__ALL__)

const char * DoShake256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SHAKE256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SHAKE256::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SHAKE256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SHAKE256::DIGESTSIZE);
            result= ToHex(lpBuffer,SHAKE256::DIGESTSIZE,algo_shake_256);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SHAKE256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SHAKE256::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SIPHASH64__ ) || defined(__ALL__)

const char * DoSipHash64(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SipHash<2,4,false>::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SipHash<2,4,false>::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SipHash<2,4,false>().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SipHash<2,4,false>::DIGESTSIZE);
            result= ToHex(lpBuffer,SipHash<2,4,false>::DIGESTSIZE,algo_sip_hash64);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SipHash<2,4,false>::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SipHash<2,4,false>::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SIPHASH128__ ) || defined(__ALL__)

const char * DoSipHash128(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SipHash<4,8,true>::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SipHash<4,8,true>::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SipHash<4,8,true>().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SipHash<4,8,true>::DIGESTSIZE);
            result= ToHex(lpBuffer,SipHash<4,8,true>::DIGESTSIZE,algo_sip_hash128);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SipHash<4,8,true>::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SipHash<4,8,true>::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __LSH224__ ) || defined(__ALL__)

const char * DoLSH224(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(LSH224::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH224::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            LSH224().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH224::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH224::DIGESTSIZE,algo_lsh_224);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(LSH224::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH224::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif
#if defined ( __LSH256__ ) || defined(__ALL__)

const char * DoLSH256(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(LSH256::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH256::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            LSH256().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH256::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH256::DIGESTSIZE,algo_lsh_256);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(LSH256::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH256::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __LSH384__ ) || defined(__ALL__)

const char * DoLSH384(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(LSH384::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH384::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            LSH384().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH384::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH384::DIGESTSIZE,algo_lsh_384);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(LSH384::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH384::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __LSH512__ ) || defined(__ALL__)

const char * DoLSH512(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(LSH512::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,LSH512::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            LSH512().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",LSH512::DIGESTSIZE);
            result= ToHex(lpBuffer,LSH512::DIGESTSIZE,algo_lsh_512);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(LSH512::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(LSH512::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __SM3__ ) || defined(__ALL__)

const char * DoSM3(const char * message)
{
    char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(SM3::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,SM3::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            SM3().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",SM3::DIGESTSIZE);
            result= ToHex(lpBuffer,SM3::DIGESTSIZE,algo_sm3);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(SM3::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(SM3::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

#if defined ( __WHIRLPOOL__ ) || defined(__ALL__)

const char * DoWhirlpool(const char * message)
{
char * lpBuffer = NULL;
    const char * result;
    if(message)
    {
        DebugMessage("Message passed in is:");
        DebugMessage(message);
        DebugMessage("\r\n");
        lpBuffer = (char * ) malloc(Whirlpool::DIGESTSIZE);
        if(lpBuffer)
        {
            memset(lpBuffer,0,Whirlpool::DIGESTSIZE);
            DebugMessage("Buffer allocated\r\n");
            Whirlpool().CalculateDigest((CryptoPP::byte *)lpBuffer, (const CryptoPP::byte *)message, strlen(message));
           DebugFormat("Processed Message to Buffer Length: %i\r\n",Whirlpool::DIGESTSIZE);
            result= ToHex(lpBuffer,Whirlpool::DIGESTSIZE,algo_whirlpool);
            if(result)
            {
                DebugMessage("Processed ToHex\r\n");
                if(strlen(result)!=(Whirlpool::DIGESTSIZE*2))
                {
                    DebugFormat("Digest result to hex is not correct size: %i - %i\r\n", strlen(result),(Whirlpool::DIGESTSIZE*2) );
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
            DebugMessage("Buffer failed allocation NULL\r\n");
        }
    }
    else
    {
        DebugMessage("Message passed in is NULL\r\n");
    }
	return NULL;
}

#endif

/*

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
*/

#ifdef __cplusplus
} 
#endif