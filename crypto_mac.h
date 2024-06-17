#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#ifdef __cplusplus

#if (defined(__MD2__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacMd2(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__MD4__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacMd4(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__MD5__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacMd5(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA1__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha1(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA224__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha224(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA256__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA384__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha384(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA512__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha512(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3224__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha3224(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3256__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha3256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3384__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha3384(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3512__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSha3512(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD128__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacRipeMd128(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD160__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacRipeMd160(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD256__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacRipeMd256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD320__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacRipeMd320(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__BLAKE2B__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacBlake2b(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__BLAKE2S__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacBlake2s(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__TIGER__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacTiger(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHAKE128__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacShake128(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHAKE256__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacShake256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SIPHASH64__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSipHash64(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SIPHASH128__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSipHash128(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH224__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacLsh224(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH256__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacLsh256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH384__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacLsh384(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH512__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacLsh512(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SM3__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacSm3(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__WHIRLPOOL__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacWhirlpool(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacCMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__CBCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacCbcCMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__DMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacDMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__GMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacGMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__HMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacHMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacPoly1305(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacTwoTrack(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
extern "C" const char * DoMacVMac(const char * key, unsigned int length, const char * message);
#endif
#else

#if (defined(__MD2__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacMd2(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__MD4__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacMd4(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__MD5__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacMd5(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA1__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha1(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA224__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha224(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA256__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA384__)|| defined(__ALL__) )&& defined(__USE_MAC__)
const char * DoMacSha384(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA512__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha512(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3224__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha3224(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3256__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha3256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3384__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha3384(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHA3512__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSha3512(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD128__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacRipeMd128(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD160__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacRipeMd160(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD256__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacRipeMd256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__RIPEMD320__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacRipeMd320(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__BLAKE2B__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacBlake2b(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__BLAKE2S__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacBlake2s(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__TIGER__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacTiger(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHAKE128__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacShake128(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SHAKE256__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacShake256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SIPHASH64__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSipHash64(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SIPHASH128__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSipHash128(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH224__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacLsh224(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH256__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacLsh256(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH384__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacLsh384(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__LSH512__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacLsh512(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__SM3__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacSm3(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__WHIRLPOOL__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacWhirlpool(const char * key, unsigned int length, const char * message);
#endif
#if defined(__CMAC__)|| defined(__ALL__)
const char * DoMacCMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__CBCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacCbcCMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacDMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacGMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacHMac(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacPoly1305(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacTwoTrack(const char * key, unsigned int length, const char * message);
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
const char * DoMacVMac(const char * key, unsigned int length, const char * message);
#endif
#endif