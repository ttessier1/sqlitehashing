#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1



#ifdef __cplusplus
extern "C" unsigned int GetDigestSize(unsigned int algoritm);
extern "C" const char * DoMd2(const char * message);
extern "C" const char * DoMd4(const char * message);
extern "C" const char * DoMd5(const char * message);
extern "C" const char * DoPanama(const char * message);
extern "C" const char * DoDES(const char * message);
extern "C" const char * DoArc4(const char * message);
extern "C" const char * DoSeal(const char * message);


// Single call 
extern "C" const char * DoSha(const char * message);
extern "C" const char * DoSha224(const char * message);
extern "C" const char * DoSha256(const char * message);
extern "C" const char * DoSha384(const char * message);
extern "C" const char * DoSha512(const char * message);
extern "C" const char * DoSha3_224(const char * message);
extern "C" const char * DoSha3_256(const char * message);
extern "C" const char * DoSha3_384(const char * message);
extern "C" const char * DoSha3_512(const char * message);

extern "C" const char * DoRipeMD128(const char * message);
extern "C" const char * DoRipeMD160(const char * message);
extern "C" const char * DoRipeMD256(const char * message);
extern "C" const char * DoRipeMD320(const char * message);

extern "C" const char * DoBlake2b(const char * message);
extern "C" const char * DoBlake2s(const char * message);

extern "C" const char * DoTiger(const char * message);

extern "C" const char * DoShake128(const char * message);
extern "C" const char * DoShake256(const char * message);

extern "C" const char * DoSipHash64(const char * message);
extern "C" const char * DoSipHash128(const char * message);

extern "C" const char * DoLSH224(const char * message);
extern "C" const char * DoLSH256(const char * message);
extern "C" const char * DoLSH384(const char * message);
extern "C" const char * DoLSH512(const char * message);

extern "C" const char * DoSM3(const char * message);
extern "C" const char * DoWhirlpool(const char * message);


// buffered
extern "C" void InitSha();
extern "C" void DoShaUpdate(const char * message, unsigned int length);
extern "C" const char * DoShaFinal(const char * message, unsigned int length);
extern "C" void UninitSha();

extern "C" const char * ToHex(const char * value, unsigned int length, unsigned int algorithm);
extern "C" unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) ;
extern "C" void FreeCryptoResult(const void * object);
extern "C" void DebugFormat( const char * format, ...);

#else
unsigned int GetDigestSize(unsigned int algoritm);
const char * DoMd2(const char * message);
const char * DoMd4(const char * message);
const char * DoMd5(const char * message);
const char * DoPanama(const char * message);
const char * DoDES(const char * message);
const char * DoArc4(const char * message);
const char * DoSeal(const char * message);

const char * DoSha(const char * message);
const char * DoSha224(const char * message);
const char * DoSha256(const char * message);
const char * DoSha384(const char * message);
const char * DoSha512(const char * message);
const char * DoSha3_224(const char * message);
const char * DoSha3_256(const char * message);
const char * DoSha3_384(const char * message);
const char * DoSha3_512(const char * message);
const char * DoRipeMD128(const char * message);
const char * DoRipeMD160(const char * message);
const char * DoRipeMD256(const char * message);
const char * DoRipeMD320(const char * message);
const char * DoBlake2b(const char * message);
const char * DoBlake2s(const char * message);
const char * DoTiger(const char * message);
const char * DoShake128(const char * message);
const char * DoShake256(const char * message);
const char * DoSipHash64(const char * message);
const char * DoSipHash128(const char * message);
const char * DoLSH224(const char * message);
const char * DoLSH256(const char * message);
const char * DoLSH384(const char * message);
const char * DoLSH512(const char * message);
const char * DoSM3(const char * message);
const char * DoWhirlpool(const char * message);

void InitSha();
void DoShaUpdate(const char * message, unsigned int length);
const char * DoShaFinal(const char * message, unsigned int length);
void UninitSha();




const char * ToHex(const char * value, unsigned int length, unsigned int algorithm);
unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) ;
void FreeCryptoResult(const void * object);
void DebugFormat( const char * format, ...);
#endif