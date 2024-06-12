#pragma once

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1



//#if defined(__MD2__) || (defined __ALL__)


typedef struct md2Context Md2Context, * Md2ContextPtr;

//#endif

#ifdef __cplusplus


//#if defined(__MD2__) || (defined __ALL__)

extern "C" Md2ContextPtr Md2Initialize();
extern "C" void Md2Update(Md2ContextPtr context, const char* message, unsigned int length);
extern "C" const char* Md2Finalize(Md2ContextPtr context);


//#endif

#else
//#if defined(__MD2__) || (defined __ALL__)

Md2ContextPtr Md2Initialize();
void Md2Update(Md2ContextPtr context, const char* message, unsigned int length);
const char* Md2Finalize(Md2ContextPtr context);

//#endif

#endif