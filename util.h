#pragma once

#define INVALID_LENGTH_VALUE INT_MAX 
#define OVERFLOW_LENGTH_VALUE INT_MAX -1
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#ifdef __cplusplus
    extern "C" unsigned int GetDigestSize(unsigned int algorithms);
    extern "C" const char * ToHexSZ(const char * value);
    extern "C" const char * ToHex(const char * value, unsigned int length, unsigned int algorithms);
    extern "C" const char * FromHex(const char * value, unsigned int length, unsigned int * resultLength);
    extern "C" const char * FromHexSZ(const char * value, unsigned int * resultLength);
    extern "C" unsigned int SelfCheckToHexSZ ( const char * value, unsigned int length) ;
    extern "C" unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) ;
#if defined(DEBUG)
    extern "C" void InitDebug();
#else
    #define InitDebug //
#endif
#if defined(DEBUG)
    extern "C" void DebugFormat( const char * format, ...);
#else
#define DebugFormat //
#endif
#if defined(DEBUG)
    extern "C" void DebugMessage(const char* message);
#else
#define DebugMessage //
#endif
    extern "C" void FreeCryptoResult(const void * object);
    extern "C" unsigned int strlength(const char* message);
    extern "C" char* strduplicate(const char* message);
#else
    unsigned int GetDigestSize(unsigned int algorithms);
    const char * ToHexSZ(const char * value);
    const char * ToHex(const char * value, unsigned int length, unsigned int algorithms);
    const char * FromHex(const char * value, unsigned int length, unsigned int * resultLength);
    const char * FromHexSZ(const char * value, unsigned int * resultLength);
    unsigned int SelfCheckToHexSZ ( const char * value, unsigned int length) ;
    unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) ;
#if defined(DEBUG)
    void InitDebug();
#else
#define InitDebug //
#endif
#if defined(DEBUG)
    void DebugFormat( const char * format, ...);
#else
#define DebugFormat //
#endif
#if defined(DEBUG)
    void DebugMessage(const char* message);
#else
#define DebugMessage //
#endif
    void FreeCryptoResult(const void * object);
    unsigned int strlength(const char* message);
    char* strduplicate(const char* message);
#endif

