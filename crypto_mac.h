#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#ifdef __cplusplus
extern "C" const char * DoMacMd2(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacMd4(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacMd5(const char * key, unsigned int length, const char * message);

extern "C" const char * DoMacSha1(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha224(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha256(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha384(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha512(const char * key, unsigned int length, const char * message);

extern "C" const char * DoMacSha3224(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha3256(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha3384(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSha3512(const char * key, unsigned int length, const char * message);

extern "C" const char * DoMacRipeMd128(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacRipeMd160(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacRipeMd256(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacRipeMd320(const char * key, unsigned int length, const char * message);

extern "C" const char * DoMacBlake2b(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacBlake2s(const char * key, unsigned int length, const char * message);

extern "C" const char * DoMacTiger(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacShake128(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacShake256(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSipHash64(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSipHash128(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacLsh224(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacLsh256(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacLsh384(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacLsh512(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacSm3(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacWhirlpool(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacCMac(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacCbcCMac(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacDMac(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacGMac(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacHMac(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacPoly1305(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacTwoTrack(const char * key, unsigned int length, const char * message);
extern "C" const char * DoMacVMac(const char * key, unsigned int length, const char * message);
  
#else
const char * DoMacMd2(const char * key, unsigned int length, const char * message);
const char * DoMacMd4(const char * key, unsigned int length, const char * message);
const char * DoMacMd5(const char * key, unsigned int length, const char * message);
const char * DoMacSha1(const char * key, unsigned int length, const char * message);
const char * DoMacSha224(const char * key, unsigned int length, const char * message);
const char * DoMacSha256(const char * key, unsigned int length, const char * message);
const char * DoMacSha384(const char * key, unsigned int length, const char * message);
const char * DoMacSha512(const char * key, unsigned int length, const char * message);
const char * DoMacSha3224(const char * key, unsigned int length, const char * message);
const char * DoMacSha3256(const char * key, unsigned int length, const char * message);
const char * DoMacSha3384(const char * key, unsigned int length, const char * message);
const char * DoMacSha3512(const char * key, unsigned int length, const char * message);
const char * DoMacRipeMd128(const char * key, unsigned int length, const char * message);
const char * DoMacRipeMd160(const char * key, unsigned int length, const char * message);
const char * DoMacRipeMd256(const char * key, unsigned int length, const char * message);
const char * DoMacRipeMd320(const char * key, unsigned int length, const char * message);
const char * DoMacBlake2b(const char * key, unsigned int length, const char * message);
const char * DoMacBlake2s(const char * key, unsigned int length, const char * message);
const char * DoMacTiger(const char * key, unsigned int length, const char * message);
const char * DoMacShake128(const char * key, unsigned int length, const char * message);
const char * DoMacShake256(const char * key, unsigned int length, const char * message);
const char * DoMacSipHash64(const char * key, unsigned int length, const char * message);
const char * DoMacSipHash128(const char * key, unsigned int length, const char * message);
const char * DoMacLsh224(const char * key, unsigned int length, const char * message);
const char * DoMacLsh256(const char * key, unsigned int length, const char * message);
const char * DoMacLsh384(const char * key, unsigned int length, const char * message);
const char * DoMacLsh512(const char * key, unsigned int length, const char * message);
const char * DoMacSm3(const char * key, unsigned int length, const char * message);
const char * DoMacWhirlpool(const char * key, unsigned int length, const char * message);
const char * DoMacCMac(const char * key, unsigned int length, const char * message);
const char * DoMacCbcCMac(const char * key, unsigned int length, const char * message);
const char * DoMacDMac(const char * key, unsigned int length, const char * message);
const char * DoMacGMac(const char * key, unsigned int length, const char * message);
const char * DoMacHMac(const char * key, unsigned int length, const char * message);
const char * DoMacPoly1305(const char * key, unsigned int length, const char * message);
const char * DoMacTwoTrack(const char * key, unsigned int length, const char * message);
const char * DoMacVMac(const char * key, unsigned int length, const char * message);
#endif