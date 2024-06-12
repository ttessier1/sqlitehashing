#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

typedef struct md2Context Md2Context, * Md2ContextPtr;


#ifdef __cplusplus

//#if defined(__MD2__) || (defined __ALL__)


extern "C" const char * DoMd2(const char * message);
extern "C" Md2ContextPtr Md2Initialize();
extern "C" void Md2Update(Md2ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md2Finalize(Md2ContextPtr context);


//#endif
#if defined(__MD4__) || (defined __ALL__)
extern "C" const char * DoMd4(const char * message);
#endif
#if defined(__MD5__) || (defined __ALL__)
extern "C" const char * DoMd5(const char * message);
#endif
#if defined(__SHA1__) || (defined __ALL__)
extern "C" const char * DoSha1(const char * message);
#endif
#if defined(__SSH224__) || (defined __ALL__)
extern "C" const char * DoSha224(const char * message);
#endif
#if defined(__SSH256__) || (defined __ALL__)
extern "C" const char * DoSha256(const char * message);
#endif
#if defined(__SSH384__) || (defined __ALL__)
extern "C" const char * DoSha384(const char * message);
#endif
#if defined(__SSH512__) || (defined __ALL__)
extern "C" const char * DoSha512(const char * message);
#endif
#if defined(__SSH3224__) || (defined __ALL__)
extern "C" const char * DoSha3_224(const char * message);
#endif
#if defined(__SSH3256__) || (defined __ALL__)
extern "C" const char * DoSha3_256(const char * message);
#endif
#if defined(__SSH3384__) || (defined __ALL__)
extern "C" const char * DoSha3_384(const char * message);
#endif
#if defined(__SSH3512__) || (defined __ALL__)
extern "C" const char * DoSha3_512(const char * message);
#endif
#if defined(__MD128__) || (defined __ALL__)
extern "C" const char * DoRipeMD128(const char * message);
#endif
#if defined(__MD160__) || (defined __ALL__)
extern "C" const char * DoRipeMD160(const char * message);
#endif
#if defined(__MD256__) || (defined __ALL__)
extern "C" const char * DoRipeMD256(const char * message);
#endif
#if defined(__MD320__) || (defined __ALL__)
extern "C" const char * DoRipeMD320(const char * message);
#endif
#if defined(__BLAKE2B__) || (defined __ALL__)
extern "C" const char * DoBlake2b(const char * message);
#endif
#if defined(__BLAKE2S__) || (defined __ALL__)
extern "C" const char * DoBlake2s(const char * message);
#endif
#if defined(__TIGER__) || (defined __ALL__)
extern "C" const char * DoTiger(const char * message);
#endif
#if defined(__SHAKE128__) || (defined __ALL__)
extern "C" const char * DoShake128(const char * message);
#endif
#if defined(__SHAKE256__) || (defined __ALL__)
extern "C" const char * DoShake256(const char * message);
#endif
#if defined(__SIPHASH64__) || (defined __ALL__)
extern "C" const char * DoSipHash64(const char * message);
#endif
#if defined(__SIPHASH128__) || (defined __ALL__)
extern "C" const char * DoSipHash128(const char * message);
#endif
#if defined(__SIPHASH224__) || (defined __ALL__)
extern "C" const char * DoLSH224(const char * message);
#endif
#if defined(__SIPHASH256__) || (defined __ALL__)
extern "C" const char * DoLSH256(const char * message);
#endif
#if defined(__SIPHASH384__) || (defined __ALL__)
extern "C" const char * DoLSH384(const char * message);
#endif
#if defined(__SIPHASH512__) || (defined __ALL__)
extern "C" const char * DoLSH512(const char * message);
#endif
#if defined(__SM3__) || (defined __ALL__)
extern "C" const char * DoSM3(const char * message);
#endif
#if defined(__WHIRLPOOL__) || (defined __ALL__)
extern "C" const char * DoWhirlpool(const char * message);
#endif

/*
extern "C" void InitSha();
extern "C" void DoShaUpdate(const char * message, unsigned int length);
extern "C" const char * DoShaFinal(const char * message, unsigned int length);
extern "C" void UninitSha();
*/
#else
//#if defined(__MD2__) || (defined __ALL__)
const char* DoMd2(const char* message);
Md2ContextPtr Md2Initialize();
void Md2Update(Md2ContextPtr context, const char* message, unsigned int length);
const char* Md2Finalize(Md2ContextPtr context);

//#endif
#if defined(__MD4__) || (defined __ALL__)
const char * DoMd4(const char * message);
#endif
#if defined(__MD5__) || (defined __ALL__)
const char * DoMd5(const char * message);
#endif
#if defined(__SHA__) || (defined __ALL__)
const char * DoSha1(const char * message);
#endif
#if defined(__SHA224__) || (defined __ALL__)
const char * DoSha224(const char * message);
#endif
#if defined(__SHA256__) || (defined __ALL__)
const char * DoSha256(const char * message);
#endif
#if defined(__SHA384__) || (defined __ALL__)
const char * DoSha384(const char * message);
#endif
#if defined(__SHA512__) || (defined __ALL__)
const char * DoSha512(const char * message);
#endif
#if defined(__SHA3224__) || (defined __ALL__)
const char * DoSha3_224(const char * message);
#endif
#if defined(__SHA3256__) || (defined __ALL__)
const char * DoSha3_256(const char * message);
#endif
#if defined(__SHA3384__) || (defined __ALL__)
const char * DoSha3_384(const char * message);
#endif
#if defined(__SHA3512__) || (defined __ALL__)
const char * DoSha3_512(const char * message);
#endif
#if defined(__MD128__) || (defined __ALL__)
const char * DoRipeMD128(const char * message);
#endif
#if defined(__MD160__) || (defined __ALL__)
const char * DoRipeMD160(const char * message);
#endif
#if defined(__MD256__) || (defined __ALL__)
const char * DoRipeMD256(const char * message);
#endif
#if defined(__MD320__) || (defined __ALL__)
const char * DoRipeMD320(const char * message);
#endif
#if defined(__BLAKE2B__) || (defined __ALL__)
const char * DoBlake2b(const char * message);
#endif
#if defined(__BLAKE2S__) || (defined __ALL__)
const char * DoBlake2s(const char * message);
#endif
#if defined(__TIGER__) || (defined __ALL__)
const char * DoTiger(const char * message);
#endif
#if defined(__SHAKE128__) || (defined __ALL__)
const char * DoShake128(const char * message);
#endif
#if defined(__SHAKE256__) || (defined __ALL__)
const char * DoShake256(const char * message);
#endif
#if defined(__SIPHASH64__) || (defined __ALL__)
const char * DoSipHash64(const char * message);
#endif
#if defined(__SIPHASH128__) || (defined __ALL__)
const char * DoSipHash128(const char * message);
#endif
#if defined(__LSH224__) || (defined __ALL__)
const char * DoLSH224(const char * message);
#endif
#if defined(__LSH256__) || (defined __ALL__)
const char * DoLSH256(const char * message);
#endif
#if defined(__LSH384__) || (defined __ALL__)
const char * DoLSH384(const char * message);
#endif
#if defined(__LSH512__) || (defined __ALL__)
const char * DoLSH512(const char * message);
#endif
#if defined(__SM3__) || (defined __ALL__)
const char * DoSM3(const char * message);
#endif
#if defined(__WHIRLPOOL__) || (defined __ALL__)
const char * DoWhirlpool(const char * message);
#endif

/*
void InitSha();
void DoShaUpdate(const char * message, unsigned int length);
const char * DoShaFinal(const char * message, unsigned int length);
void UninitSha();
*/

#endif