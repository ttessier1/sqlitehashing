#pragma once

#ifdef __cplusplus
    extern "C" unsigned int GetDigestSize(unsigned int algorithms);
    extern "C" const char * ToHexSZ(const char * value);
    extern "C" const char * ToHex(const char * value, unsigned int length, unsigned int algorithms);
    extern "C" const char * FromHex(const char * value, unsigned int length, unsigned int * resultLength);
    extern "C" const char * FromHexSZ(const char * value, unsigned int * resultLength);
    extern "C" unsigned int SelfCheckToHexSZ ( const char * value, unsigned int length) ;
    extern "C" unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) ;
    extern "C" void DebugFormat( const char * format, ...);
    extern "C" void FreeCryptoResult(const void * object);
#else
    unsigned int GetDigestSize(unsigned int algorithms);
    const char * ToHexSZ(const char * value);
    const char * ToHex(const char * value, unsigned int length, unsigned int algorithms);
    const char * FromHex(const char * value, unsigned int length, unsigned int * resultLength);
    const char * FromHexSZ(const char * value, unsigned int * resultLength);
    unsigned int SelfCheckToHexSZ ( const char * value, unsigned int length) ;
    unsigned int SelfCheckToHex ( const char * value, unsigned int length, unsigned int algorithm) ;
    void DebugFormat( const char * format, ...);
    void FreeCryptoResult(const void * object);
#endif

