#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "crypto_hashing.h"
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
#include <ttmac.h>
#include <aes.h>
#include <hex.h>
#include "algorithms.h"

#include "util.h"

#include <cstdarg>
#include <sstream>

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

const char * hexChars = "0123456789ABCDEF";

unsigned int GetDigestSize(unsigned int algorithms)
{
    switch(algorithms)
        {
    case -1:

        break;
#if defined ( __MD2__ ) || defined(__ALL__)
            case algo_md2:
            case algo_hmac_md2:
                return MD2::DIGESTSIZE ;
            break;
#endif
#if defined ( __MD4__ ) || defined(__ALL__)
            case algo_md4:
            case algo_hmac_md4:
                return MD4::DIGESTSIZE ;
            break;
#endif
#if defined ( __MD5__ ) || defined(__ALL__)
            case algo_md5:
            case algo_hmac_md5:
                return MD5::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA1__ ) || defined(__ALL__)
            case algo_sha1:
            case algo_hmac_sha1:
                return  SHA1::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA224__ ) || defined(__ALL__)
            case algo_sha224:
            case algo_hmac_sha224:
                return SHA224::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA256__ ) || defined(__ALL__)
            case algo_sha256:
            case algo_hmac_sha256:
                return SHA256::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA384__ ) || defined(__ALL__)
            case algo_sha384:
            case algo_hmac_sha384:
                return SHA384::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA512__ ) || defined(__ALL__)
            case algo_sha512:
            case algo_hmac_sha512:
                return SHA512::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA3224__ ) || defined(__ALL__)
            case algo_sha3_224:
            case algo_hmac_sha3_224:
                return SHA3_224::DIGESTSIZE ;
            break;
#endif
#if defined ( __MD3256__ ) || defined(__ALL__)
            case algo_sha3_256:
            case algo_hmac_sha3_256:
                return SHA3_256::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA3384__ ) || defined(__ALL__)
            case algo_sha3_384:
            case algo_hmac_sha3_384:
                return SHA3_384::DIGESTSIZE ;
            break;
#endif
#if defined ( __SHA3512__ ) || defined(__ALL__)
            case algo_sha3_512:
            case algo_hmac_sha3_512:
                return SHA3_512::DIGESTSIZE ;
            break;
#endif
#if defined ( __RIPEMD128__ ) || defined(__ALL__)
            case algo_ripemd_128:
            case algo_hmac_ripemd_128:
                return RIPEMD128::DIGESTSIZE ;
            break;
#endif
#if defined ( __RIPEMD160__ ) || defined(__ALL__)
            case algo_ripemd_160:
            case algo_hmac_ripemd_160:
                return RIPEMD160::DIGESTSIZE ;
            break;
#endif
#if defined ( __RIPEMD256__ ) || defined(__ALL__)
            case algo_ripemd_256:
            case algo_hmac_ripemd_256:
                return RIPEMD256::DIGESTSIZE ;
            break;
#endif
#if defined ( __RIPEMD320__ ) || defined(__ALL__)
            case algo_ripemd_320:
            case algo_hmac_ripemd_320:
                return RIPEMD320::DIGESTSIZE ;
            break;
#endif
#if defined ( __NBLAKE2B__ ) || defined(__ALL__)
            case algo_blake2b:
            case algo_hmac_blake2b:
                return BLAKE2b::DIGESTSIZE;
            break;
#endif
#if defined ( __BLAKE2S__ ) || defined(__ALL__)
            case algo_blake2s:
            case algo_hmac_blake2s:
                return BLAKE2s::DIGESTSIZE;
            break;
#endif
#if defined ( __TIGER__ ) || defined(__ALL__)
            case algo_tiger:
            case algo_hmac_tiger:
                return Tiger::DIGESTSIZE;
            break;
#endif
#if defined ( __SHAKE128__ ) || defined(__ALL__)
            case algo_shake_128:
            case algo_hmac_shake_128:
                return SHAKE128::DIGESTSIZE;
            break;
#endif
#if defined ( __SHAKE256__ ) || defined(__ALL__)
            case algo_shake_256:
            case algo_hmac_shake_256:
                return SHAKE256::DIGESTSIZE;
            break;
#endif
#if defined ( __SIPHASH64__ ) || defined(__ALL__)
            case algo_sip_hash64:
            case algo_hmac_sip_hash64:
                return SipHash<2,4,false>::DIGESTSIZE;
            break;
#endif
#if defined ( __SIPHASH128__ ) || defined(__ALL__)
            case algo_sip_hash128:
            case algo_hmac_sip_hash128:
                return SipHash<4,8,true>::DIGESTSIZE;
            break;
#endif
#if defined ( __LSH224__ ) || defined(__ALL__)
            case algo_lsh_224:
            case algo_hmac_lsh_224:
                return LSH224::DIGESTSIZE;
            break;
#endif
#if defined ( __LSH256__ ) || defined(__ALL__)
            case algo_lsh_256:
            case algo_hmac_lsh_256:
                return LSH256::DIGESTSIZE;
            break;
#endif
#if defined ( __LSH384__ ) || defined(__ALL__)
            case algo_lsh_384:
            case algo_hmac_lsh_384:
                return LSH384::DIGESTSIZE;
            break;
#endif
#if defined ( __LSH512__ ) || defined(__ALL__)
            case algo_lsh_512:
            case algo_hmac_lsh_512:
                return LSH512::DIGESTSIZE;
            break;
#endif
#if defined ( __SM3__ ) || defined(__ALL__)
            case algo_sm3:
            case algo_hmac_sm3:
                return SM3::DIGESTSIZE;
            break;
#endif
#if defined ( __WHIRLPOOL__ ) || defined(__ALL__)
            case algo_whirlpool:
            case algo_hmac_whirlpool:
                return Whirlpool::DIGESTSIZE;
            break;
#endif
#if defined(__CMAC__)|| defined(__ALL__)
            case algo_cmac:
                return AES::BLOCKSIZE;
            break;
#endif
#if defined(__CBCCMAC__)|| defined(__ALL__)
            case algo_cbc_mac:
                return AES::BLOCKSIZE;
                break;
#endif
#if defined(__DMAC__)|| defined(__ALL__)
            case algo_dmac:
                return AES::BLOCKSIZE;
                break;
#endif
#if defined(__GMAC__)|| defined(__ALL__)
            case algo_gmac:
                return AES::BLOCKSIZE;
                break;
#endif
#if defined(__HMAC__)|| defined(__ALL__)
            case algo_hmac:
                return SHA256::DIGESTSIZE;
                break;

#endif
#if defined(__POLY1305__)|| defined(__ALL__)
            case algo_poly_1305:
                return AES::BLOCKSIZE;
                break;
#endif
#if defined(__TWOTRACK__)|| defined(__ALL__)
            case algo_two_track:
                return TTMAC::DIGESTSIZE;
                    break;
#endif
#if defined(__VMAC__)|| defined(__ALL__)
            case algo_vmac:
                return AES::BLOCKSIZE;
                break;
#endif
            default :
                return 0;
        }
        return 0;
}

const char * ToHexSZ(const char * value)
{
    char * hexValue = NULL;
    char theChar =0;
    unsigned int maxLength = 0 ;
    unsigned int index=0;
    unsigned int valueIndex=0;
    unsigned int length = 0 ;
    if ( value )
    {
        length = strlength(value);
        maxLength = length*2;
        hexValue = ( char * ) malloc((maxLength)+1);
        if(hexValue)
        {
            for(index = 0 ; index< length ;index++)
            {
                if (valueIndex > (maxLength))
                {

                    break;
                }
                theChar = (((value[index]&0xF0)>>4)&0x0F);
                hexValue[valueIndex] = hexChars[theChar];
                
                DebugFormat("ToHexSZ: Index:%i ValueIndex:%i Initial: %x Char: %i Value: %i\r\n",index,valueIndex,value[index],theChar, hexValue[valueIndex]);
                valueIndex++;
                if (valueIndex > (maxLength))
                {

                    break;
                }
                theChar = ((value[index])&0x0F);
                hexValue[valueIndex] = hexChars[theChar];
               
                DebugFormat("ToHexSZ: Index:%i ValueIndex:%i Initial: %x Char: %i Value: %i\r\n",index,valueIndex,value[index],theChar, hexValue[valueIndex]);
                valueIndex++;
            }
            hexValue[maxLength]='\0';
            if(SelfCheckToHexSZ(hexValue,maxLength)!=1)
            {
                DebugFormat("ToHexSZ: hexValue Failed to SelfCheck\r\n");
                return NULL;
            }
        }
        else
        {
            DebugFormat("ToHexSZ: hexValue Failed to allocated\r\n");
            return NULL;
        }
    }
    else
    {
        DebugFormat("ToHexSZ: Value is NULL\r\n");
        return NULL;
    }
    return hexValue;
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
        case -1:

            break;
#if defined ( __MD2__ ) || defined(__ALL__)
            case algo_md2:
            case algo_hmac_md2:
                if(length!=MD2::DIGESTSIZE)
                {
                    DebugFormat("MD2 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,MD2::DIGESTSIZE);
                    return NULL;
                }
                maxLength = MD2::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __MD4__ ) || defined(__ALL__)
            case algo_md4:
            case algo_hmac_md4:
                if(length!=MD4::DIGESTSIZE)
                {
                    DebugFormat("MD4 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,MD4::DIGESTSIZE);
                    return NULL;
                }
                maxLength = MD4::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __MD5__ ) || defined(__ALL__)
            case algo_md5:
            case algo_hmac_md5:
                if(length!=MD5::DIGESTSIZE)
                {
                    DebugFormat("MD5 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,MD5::DIGESTSIZE);
                    return NULL;
                }
                maxLength = MD5::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA1__ ) || defined(__ALL__)
            case algo_sha1:
            case algo_hmac_sha1:
                if(length!=SHA1::DIGESTSIZE)
                {
                    DebugFormat("SHA1 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA1::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA224__ ) || defined(__ALL__)
            case algo_sha224:
            case algo_hmac_sha224:
                if(length!=SHA224::DIGESTSIZE)
                {
                    DebugFormat("SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA224::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA256__ ) || defined(__ALL__)
            case algo_sha256:
            case algo_hmac_sha256:
                if(length!=SHA256::DIGESTSIZE)
                {
                    DebugFormat("SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA384__ ) || defined(__ALL__)
            case algo_sha384:
            case algo_hmac_sha384:
                if(length!=SHA384::DIGESTSIZE)
                {
                    DebugFormat("SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA384::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA512__ ) || defined(__ALL__)
            case algo_sha512:
            case algo_hmac_sha512:
                if(length!=SHA512::DIGESTSIZE)
                {
                    DebugFormat("SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA512::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA512::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA3224__ ) || defined(__ALL__)
            case algo_sha3_224:
            case algo_hmac_sha3_224:
                if(length!=SHA224::DIGESTSIZE)
                {
                    DebugFormat("SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA224::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA3256__ ) || defined(__ALL__)
            case algo_sha3_256:
            case algo_hmac_sha3_256:
                if(length!=SHA256::DIGESTSIZE)
                {
                    DebugFormat("SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA3384__ ) || defined(__ALL__)
            case algo_sha3_384:
            case algo_hmac_sha3_384:
                if(length!=SHA384::DIGESTSIZE)
                {
                    DebugFormat("SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA1::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA384::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA3512__ ) || defined(__ALL__)
            case algo_sha3_512:
            case algo_hmac_sha3_512:
                if(length!=SHA512::DIGESTSIZE)
                {
                    DebugFormat("SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHA512::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA512::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD128__ ) || defined(__ALL__)
            case algo_ripemd_128:
            case algo_hmac_ripemd_128:
                if(length!=RIPEMD128::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD128 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD128::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD128::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD160__ ) || defined(__ALL__)
            case algo_ripemd_160:
            case algo_hmac_ripemd_160:
                if(length!=RIPEMD160::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD160 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD160::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD160::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD256__ ) || defined(__ALL__)
            case algo_ripemd_256:
            case algo_hmac_ripemd_256:
                if(length!=RIPEMD256::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD320__ ) || defined(__ALL__)
            case algo_ripemd_320:
            case algo_hmac_ripemd_320:
                if(length!=RIPEMD320::DIGESTSIZE)
                {
                    DebugFormat("RIPEMD320 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,RIPEMD320::DIGESTSIZE);
                    return NULL;
                }
                maxLength = RIPEMD320::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __BLAKE2B__ ) || defined(__ALL__)
            case algo_blake2b:
            case algo_hmac_blake2b:
                if(length!=BLAKE2b::DIGESTSIZE)
                {
                    DebugFormat("BLAKE2b Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,BLAKE2b::DIGESTSIZE);
                    return NULL;
                }
                maxLength = BLAKE2b::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __BLAKE2S__ ) || defined(__ALL__)
            case algo_blake2s:
            case algo_hmac_blake2s:
                if(length!=BLAKE2s::DIGESTSIZE)
                {
                    DebugFormat("BLAKE2s Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,BLAKE2s::DIGESTSIZE);
                    return NULL;
                }
                maxLength = BLAKE2s::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __TIGER__ ) || defined(__ALL__)
            case algo_tiger:
            case algo_hmac_tiger:
                if(length!=Tiger::DIGESTSIZE)
                {
                    DebugFormat("Tiger Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Tiger::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Tiger::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHAKE128__ ) || defined(__ALL__)
            case algo_shake_128:
            case algo_hmac_shake_128:
                if(length!=SHAKE128::DIGESTSIZE)
                {
                    DebugFormat("SHAKE128 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHAKE128::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHAKE128::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHAKE256__ ) || defined(__ALL__)
            case algo_shake_256:
            case algo_hmac_shake_256:
                if(length!=SHAKE256::DIGESTSIZE)
                {
                    DebugFormat("SHAKE256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SHAKE256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHAKE256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SIPHASH64__ ) || defined(__ALL__)
            case algo_sip_hash64:
            case algo_hmac_sip_hash64:
                if(length!=SipHash<2,4,false>::DIGESTSIZE)
                {
                    DebugFormat("SipHash64 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SipHash<2,4,false>::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SipHash<2,4,false>::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SIPHASH128__ ) || defined(__ALL__)
            case algo_sip_hash128:
            case algo_hmac_sip_hash128:
                if(length!=SipHash<4,8,true>::DIGESTSIZE)
                {
                    DebugFormat("SipHash128 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SipHash<4,8,true>::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SipHash<4,8,true>::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH224__ ) || defined(__ALL__)
            case algo_lsh_224:
            case algo_hmac_lsh_224:
                if(length!=LSH224::DIGESTSIZE)
                {
                    DebugFormat("LSH224 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH224::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH224::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH256__ ) || defined(__ALL__)
            case algo_lsh_256:
            case algo_hmac_lsh_256:
                if(length!=LSH256::DIGESTSIZE)
                {
                    DebugFormat("LSH256 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH384__ ) || defined(__ALL__)
            case algo_lsh_384:
            case algo_hmac_lsh_384:
                if(length!=LSH384::DIGESTSIZE)
                {
                    DebugFormat("LSH384 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH384::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH384::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH512__ ) || defined(__ALL__)
            case algo_lsh_512:
            case algo_hmac_lsh_512:
                if(length!=LSH512::DIGESTSIZE)
                {
                    DebugFormat("LSH512 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,LSH512::DIGESTSIZE);
                    return NULL;
                }
                maxLength = LSH512::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SM3__ ) || defined(__ALL__)
            case algo_sm3:
            case algo_hmac_sm3:
                if(length!=SM3::DIGESTSIZE)
                {
                    DebugFormat("SM3 Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,SM3::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SM3::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __WHIRLPOOL__ ) || defined(__ALL__)
            case algo_whirlpool:
            case algo_hmac_whirlpool:
                if(length!=Whirlpool::DIGESTSIZE)
                {
                    DebugFormat("Whirlpool Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,Whirlpool::DIGESTSIZE);
                    return NULL;
                }
                maxLength = Whirlpool::DIGESTSIZE*2 ;
            break;
#endif
#if defined(__CMAC__)|| defined(__ALL__)
            case algo_cmac:
                if(length!=AES::BLOCKSIZE)
                {
                    DebugFormat("AES Algorithm Length does not match actual length: [%i] [%i]\r\n,",length,AES::BLOCKSIZE);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE*2 ;
            break;
#endif
#if defined(__CBCCMAC__)|| defined(__ALL__)
            case algo_cbc_mac:
                if (length != AES::BLOCKSIZE)
                {
                    DebugFormat("AES Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, AES::BLOCKSIZE);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__DMAC__)|| defined(__ALL__)
            case algo_dmac:
                if (length != AES::BLOCKSIZE)
                {
                    DebugFormat("AES Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, AES::BLOCKSIZE);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__GMAC__)|| defined(__ALL__)
            case algo_gmac:
                if (length != AES::BLOCKSIZE)
                {
                    DebugFormat("AES Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, AES::BLOCKSIZE);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__HMAC__)|| defined(__ALL__)
            case algo_hmac:
                if (length != SHA256::DIGESTSIZE)
                {
                    DebugFormat("AES Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, SHA256::DIGESTSIZE);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE * 2;
                break;
#endif
#if defined(__POLY1305__)|| defined(__ALL__)
            case algo_poly_1305:
                if (length != AES::BLOCKSIZE)
                {
                    DebugFormat("SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, AES::BLOCKSIZE);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__TWOTRACK__)|| defined(__ALL__)
            case algo_two_track:
                if (length != TTMAC::DIGESTSIZE)
                {
                    DebugFormat("TwoTrack Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, TTMAC::DIGESTSIZE);
                    return NULL;
                }
                maxLength = TTMAC::DIGESTSIZE * 2;
                break;
#endif
#if defined(__VMAC__)|| defined(__ALL__)
            case algo_vmac:
                if (length != AES::BLOCKSIZE)
                {
                    DebugFormat("Vmac Algorithm Length does not match actual length: [%i] [%i]\r\n,", length, AES::BLOCKSIZE);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
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

unsigned int SelfCheckToHexSZ ( const char * value, unsigned int length) 
{
    unsigned int index=0;
    unsigned int maxLength=0;
    if ( value )
    {
        if(((length%2)==0)&& (length>0))
        {
            for(index=0;index<maxLength;index++)
            {
                if(
                    (value[index]>='0' && value[index]<='9')||
                    (value[index]>='a' && value[index]<='f')||
                    (value[index]>='A' && value[index]<='F')
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
            DebugFormat("Length is Incorrect\r\n");    
        }
    }
    else
    {
        DebugFormat("Value is NULL\r\n");
    }
    return 0;
}

unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) 
{
    unsigned int index=0;
    unsigned int maxLength=0;
    if ( value )
    {
        switch(algorithm)
        {
        case -1:
            break;
#if defined ( __MD2__ ) || defined(__ALL__)
            case algo_md2:
            case algo_hmac_md2:
                if(length!=MD2::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck MD2 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,MD2::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = MD2::DIGESTSIZE *2;
            break;
#endif
#if defined ( __MD4__ ) || defined(__ALL__)
            case algo_md4:
            case algo_hmac_md4:
                if(length!=MD4::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck MD4 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,MD4::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = MD4::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __MD5__ ) || defined(__ALL__)
            case algo_md5:
            case algo_hmac_md5:
                if(length!=MD5::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck MD5 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,MD5::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = MD5::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA1__ ) || defined(__ALL__)
            case algo_sha1:
            case algo_hmac_sha1:
                if(length!=SHA1::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA1 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA1::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA1::DIGESTSIZE *2;
            break;
#endif
#if defined ( __SHA224__ ) || defined(__ALL__)
            case algo_sha224:
            case algo_hmac_sha224:
                if(length!=SHA224::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA224 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA224::DIGESTSIZE*2;
            break;
#endif
#if defined ( __SHA256__ ) || defined(__ALL__)
            case algo_sha256:
            case algo_hmac_sha256:
                if(length!=SHA256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE*2;
            break;
#endif
#if defined ( __SHA384__ ) || defined(__ALL__)
            case algo_sha384:
            case algo_hmac_sha384:
                if(length!=SHA384::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA384 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA384::DIGESTSIZE*2;
            break;
#endif
#if defined ( __SHA512__ ) || defined(__ALL__)
            case algo_sha512:
            case algo_hmac_sha512:
                if(length!=SHA512::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA512 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA512::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA512::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHA3224__ ) || defined(__ALL__)
            case algo_sha3_224:
            case algo_hmac_sha3_224:
                if(length!=SHA3_224::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_224 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_224::DIGESTSIZE*2;
            break;
#endif
#if defined ( __SHA3256__ ) || defined(__ALL__)
            case algo_sha3_256:
            case algo_hmac_sha3_256:
                if(length!=SHA3_256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_256::DIGESTSIZE*2;
            break;
#endif
#if defined ( __SHA3384__ ) || defined(__ALL__)
            case algo_sha3_384:
            case algo_hmac_sha3_384:
                if(length!=SHA3_384::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_384 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_384::DIGESTSIZE*2;
            break;
#endif
#if defined ( __SHA3512__ ) || defined(__ALL__)
            case algo_sha3_512:
            case algo_hmac_sha3_512:
                if(length!=SHA3_512::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHA3_512 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHA512::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHA3_512::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD128__ ) || defined(__ALL__)
            case algo_ripemd_128:
            case algo_hmac_ripemd_128:
                if(length!=RIPEMD128::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD128 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD128::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD128::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD160__ ) || defined(__ALL__)
            case algo_ripemd_160:
            case algo_hmac_ripemd_160:
                if(length!=RIPEMD160::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD160 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD160::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD160::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD256__ ) || defined(__ALL__)
            case algo_ripemd_256:
            case algo_hmac_ripemd_256:
                if(length!=RIPEMD256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __RIPEMD320__ ) || defined(__ALL__)
            case algo_ripemd_320:
            case algo_hmac_ripemd_320:
                if(length!=RIPEMD320::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck RIPEMD320 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,RIPEMD320::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = RIPEMD320::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __BLAKE2B__ ) || defined(__ALL__)
            case algo_blake2b:
            case algo_hmac_blake2b:
                if(length!=BLAKE2b::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck BLAKE2b Algorithm Length does not match actual length: [%i] [%i]\r\n",length,BLAKE2b::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = BLAKE2b::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __BLAKE2S__ ) || defined(__ALL__)
            case algo_blake2s:
            case algo_hmac_blake2s:
                if(length!=BLAKE2s::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck BLAKE2s Algorithm Length does not match actual length: [%i] [%i]\r\n",length,BLAKE2s::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = BLAKE2s::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __TIGER__ ) || defined(__ALL__)
            case algo_tiger:
            case algo_hmac_tiger:
                if(length!=Tiger::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck Tiger Algorithm Length does not match actual length: [%i] [%i]\r\n",length,Tiger::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = Tiger::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHAKE128__ ) || defined(__ALL__)
            case algo_shake_128:
            case algo_hmac_shake_128:
                if(length!=SHAKE128::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHAKE128 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHAKE128::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHAKE128::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SHAKE256__ ) || defined(__ALL__)
            case algo_shake_256:
            case algo_hmac_shake_256:
                if(length!=SHAKE256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SHAKE256 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SHAKE256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SHAKE256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SIPHASH64__ ) || defined(__ALL__)
            case algo_sip_hash64:
            case algo_hmac_sip_hash64:
                if(length!=SipHash<2,4,false>::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SipHash64 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SipHash<2,4,false>::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SipHash<2,4,false>::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SIPHASH128__ ) || defined(__ALL__)
            case algo_sip_hash128:
            case algo_hmac_sip_hash128:
                if(length!=SipHash<4,8,true>::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SipHash128 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SipHash<4,8,true>::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SipHash<4,8,true>::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH224__ ) || defined(__ALL__)
            case algo_lsh_224:
            case algo_hmac_lsh_224:
                if(length!=LSH224::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH224 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH224::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH224::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH256__ ) || defined(__ALL__)
            case algo_lsh_256:
            case algo_hmac_lsh_256:
                if(length!=LSH256::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH256 Tiger Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH256::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH256::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH384__ ) || defined(__ALL__)
            case algo_lsh_384:
            case algo_hmac_lsh_384:
                if(length!=LSH384::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH384 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH384::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH384::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __LSH512__ ) || defined(__ALL__)
            case algo_lsh_512:
            case algo_hmac_lsh_512:
                if(length!=LSH512::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck LSH512 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,LSH512::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = LSH512::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __SM3__ ) || defined(__ALL__)
            case algo_sm3:
            case algo_hmac_sm3:
                if(length!=SM3::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck SM3 Algorithm Length does not match actual length: [%i] [%i]\r\n",length,SM3::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = SM3::DIGESTSIZE*2 ;
            break;
#endif
#if defined ( __WHIRLPOOL__ ) || defined(__ALL__)
            case algo_whirlpool:
            case algo_hmac_whirlpool:
                if(length!=Whirlpool::DIGESTSIZE*2)
                {
                    DebugFormat("SelfCheck Whirlpool Algorithm Length does not match actual length: [%i] [%i]\r\n",length,Whirlpool::DIGESTSIZE*2);
                    return NULL;
                }
                maxLength = Whirlpool::DIGESTSIZE*2 ;
            break;
#endif
#if defined(__CMAC__)|| defined(__ALL__)
            case algo_cmac:
                if(length!=AES::BLOCKSIZE*2)
                {
                    DebugFormat("SelfCheck CMAC Algorithm Length does not match actual length: [%i] [%i]\r\n",length,AES::BLOCKSIZE*2);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE*2 ;
            break;
#endif
#if defined(__CBCCMAC__)|| defined(__ALL__)
            case algo_cbc_mac:
                if (length != AES::BLOCKSIZE * 2)
                {
                    DebugFormat("SelfCheck CMAC_CBC Algorithm Length does not match actual length: [%i] [%i]\r\n", length, AES::BLOCKSIZE * 2);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__DMAC__)|| defined(__ALL__)
            case algo_dmac:
                if (length != AES::BLOCKSIZE * 2)
                {
                    DebugFormat("SelfCheck DMAC Algorithm Length does not match actual length: [%i] [%i]\r\n", length, AES::BLOCKSIZE * 2);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__GMAC__)|| defined(__ALL__)
            case algo_gmac:
                if (length != AES::BLOCKSIZE * 2)
                {
                    DebugFormat("SelfCheck GMAC Algorithm Length does not match actual length: [%i] [%i]\r\n", length, AES::BLOCKSIZE * 2);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__HMAC__)|| defined(__ALL__)
            case algo_hmac:
                if (length != SHA256::DIGESTSIZE * 2)
                {
                    DebugFormat("SelfCheck HMAC Algorithm Length does not match actual length: [%i] [%i]\r\n", length, SHA256::DIGESTSIZE * 2);
                    return NULL;
                }
                maxLength = SHA256::DIGESTSIZE * 2;
                break;
#endif
#if defined(__POLY1305__)|| defined(__ALL__)
            case algo_poly_1305:
                if (length != AES::BLOCKSIZE * 2)
                {
                    DebugFormat("SelfCheck Poly1305 Algorithm Length does not match actual length: [%i] [%i]\r\n", length, AES::BLOCKSIZE * 2);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
#if defined(__TWOTRACK__)|| defined(__ALL__)
            case algo_two_track:
                if (length != TTMAC::DIGESTSIZE* 2)
                {
                    DebugFormat("SelfCheck TTMac Algorithm Length does not match actual length: [%i] [%i]\r\n", length, TTMAC::DIGESTSIZE * 2);
                    return NULL;
                }
                maxLength = TTMAC::DIGESTSIZE * 2;
                break;
#endif
#if defined(__VMAC__)|| defined(__ALL__)
            case algo_vmac:
                if (length != AES::BLOCKSIZE * 2)
                {
                    DebugFormat("SelfCheck VMAC Algorithm Length does not match actual length: [%i] [%i]\r\n", length, AES::BLOCKSIZE * 2);
                    return NULL;
                }
                maxLength = AES::BLOCKSIZE * 2;
                break;
#endif
            default :
                DebugFormat("Invalid Algorithm: [%i] [%i]\r\n",algorithm);
                return 0;
        }
        for(index=0;index<maxLength;index++)
        {
            if(
                (value[index]>='0' && value[index]<='9')||
                (value[index]>='a' && value[index]<='f')||
                (value[index]>='A' && value[index]<='F')
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

const char * FromHex(const char * value, unsigned int length, unsigned int * resultLength)
{
    char * result=NULL;
    char theChar=0;
    unsigned int index=0;
    unsigned int valueIndex=0;
    unsigned int actualLength = 0;
    if(value)
    {
        if(((length%2)==0)&&(length>0))
        {
            actualLength = length / 2;
            result = (char * ) malloc(actualLength+1);
            if(result!=NULL)
            {
                for(index=0;index< length;index+=2)
                {
                    theChar=0;
                    if(
                        ((value[index]>='0' && value[index]<='9')||
                        (value[index]>='a' && value[index]<='f')||
                        (value[index]>='A' && value[index]<='F'))
                        &&
                        ((value[index+1]>='0' && value[index+1]<='9')||
                        (value[index+1]>='a' && value[index+1]<='f')||
                        (value[index+1]>='A' && value[index+1]<='F'))
                    )
                    {
                        DebugFormat("Index: %i Value: %c %c\r\n", index, value[index],value[index+1]);
                        result[valueIndex]=0;
                        theChar = value[index];
                        if(theChar>'9')
                        {
                            result[valueIndex] += (theChar-0x3A)<<4;
                        }
                        else
                        {
                            result[valueIndex] += (theChar-0x30)<<4;
                        }
                        theChar = value[index+1];
                        if(theChar>'9')
                        {
                            result[valueIndex] += (theChar-0x3A);
                        }
                        else
                        {
                            result[valueIndex] += (theChar-0x30);
                        }
                        valueIndex++;
                        if (valueIndex >= actualLength)
                        {
                            
                            // array past bounds
                            DebugFormat("Index Past Bounds: [%i] [%i]\r\n",valueIndex,actualLength);
                            break;
                        }
                    }
                    else
                    {
                        free(result);
                        result=NULL;
                        DebugFormat("Index: %i Value: %c %c\r\n", index, value[index],value[index+1]);
                        return NULL;
                    }
                }
                result[actualLength] ='\0';
                if(resultLength)
                {
                    *resultLength = (length/2);
                }
            }
            else
            {
                DebugMessage("FromHex: Failed to allocate\r\n");
            }
        }
        else
        {
            DebugFormat("FromHex: [%s] Length is incorrect: %i\r\n",value, length );
        }
    }
    else
    {
        DebugMessage("FromHex: Value is NULL");
    }
    return result;
}

const char * FromHexSZ(const char * value, unsigned int * resultLength)
{
    char * result=NULL;
    char theChar=0;
    unsigned int index=0;
    unsigned int length = 0 ;
    unsigned int valueIndex=0;
    if(value)
    {
        length = strlength(value);
        if(((length%2)==0)&&(length>0))
        {
            
            result = (char * ) malloc((length/2)+1);
            if(result)
            {
                for(index=0;index<length;index+=2)
                {
                    theChar=0;
                    if(
                        ((value[index]>='0' && value[index]<='9')||
                        (value[index]>='a' && value[index]<='f')||
                        (value[index]>='A' && value[index]<='F'))
                        &&
                        ((value[index+1]>='0' && value[index+1]<='9')||
                        (value[index+1]>='a' && value[index+1]<='f')||
                        (value[index+1]>='A' && value[index+1]<='F'))
                    )
                    {
                        DebugFormat("Index: %i Value: %c %c\r\n", index, value[index],value[index+1]);
                        result[valueIndex]=0;
                        theChar = value[index];
                        if(theChar>'9')
                        {
                            result[valueIndex] += (theChar-0x3A)<<4;
                        }
                        else
                        {
                            result[valueIndex] += (theChar-0x30)<<4;
                        }
                        theChar = value[index+1];
                        if(theChar>'9')
                        {
                            result[valueIndex] += (theChar-0x3A);
                        }
                        else
                        {
                            result[valueIndex] += (theChar-0x30);
                        }
                        valueIndex++;
                    }
                    else
                    {
                        free(result);
                        result=NULL;
                        DebugFormat("Index: %i Value: %c %c\r\n", index, value[index],value[index+1]);
                        return NULL;
                    }
                }
                result[(length / 2)] ='\0';
                if(resultLength)
                {
                    *resultLength = (length/2);
                }
            }
            else
            {
                DebugMessage("FromHexSZ: Failed to allocated\r\n");
            }
        }
        else
        {
            DebugFormat("FromHexSZ: [%s] Length is incorrect: %i\r\n",value, length );
        }
    }
    else
    {
        DebugMessage("FromHexSZ: Value is NULL");
    }
    return result;
}

#if defined(DEBUG)
void InitDebug()
{
#if defined(_WIN32)
#else

#endif
}
#endif

#if defined(DEBUG)

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
    DebugMessage(outputStream.str().c_str());
}

#else

#endif

#if defined(DEBUG)
void DebugMessage(const char* message)
{
    if (message != NULL)
    {

#if defined _WIN32 
        DebugMessage(message);
#else

#endif

    }
}
#else

#endif


void FreeCryptoResult(const void * object)
{
    if(object!=NULL)
    {
        free((void*)object);
    }
}

// non optimized strlength
unsigned int strlength(const char* message)
{
    unsigned int length = 0;
    if (message != NULL)
    {
        while (*message != '\0')
        {
            message++;
            if (length > INT_MAX - 1)
            {
                return OVERFLOW_LENGTH_VALUE;
            }
            length++;
        }
    }
    else
    { 
        return INVALID_LENGTH_VALUE;
    }
    return length;
}

char* strduplicate(const char* message)
{
    char* duplicate = NULL;
    unsigned int length = 0;
    if (message != NULL)
    {
        length = strlength(message);
        if (length != INVALID_LENGTH_VALUE)
        {
            duplicate = (char*)malloc(length + 1);
            if (duplicate != NULL)
            {
                strcpy_s(duplicate,length+1,message);
            }
        }
        return duplicate;
    }
    return duplicate;
}

#ifdef __cplusplus
}
#endif