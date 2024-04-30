/* Add your header comment here */
#include <inttypes.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN      // Exclude rarely-used stuff from Windows headers

#include <windows.h>
#include "algorithms.h"
#include "util.h"
#include "crypto_hashing.h"
#include "crypto_mac.h"

SQLITE_EXTENSION_INIT1

#include "hashsizes.h"
#include "hashinfo.h"

#include <stdio.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define PING_MESSAGE "ping"

static unsigned char rot13c(unsigned char c)
{
    if(c>='a' && c <='z')
    {
        c+=13;
        if(c>='z')
        {
            c -= 26;
        }
    }
    else if ( c >='A' && c <= 'Z')
    {
        c+=13;
        if(c>'Z')
        {
            c -= 26;
        }
    }
    return c;
}

static int hash_ping(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    nIn = strlength(PING_MESSAGE);
    if(argc!=0)
    {
        return-1;
    }
    zOut = zToFree = (unsigned char * ) sqlite3_malloc64(nIn+1);
    if(zOut == 0 )
    {
        sqlite3_result_error_nomem(context);
        return-1;
    }
    strcpy_s(zOut,nIn+1,PING_MESSAGE);
    
    sqlite3_result_text(context, (char*) zOut, nIn, SQLITE_TRANSIENT);
    sqlite3_free(zToFree);
    return 0;
}

static int rot13(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    if(argc!=1)
    {
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL) return -1;
    zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
    nIn = sqlite3_value_bytes(argv[0]);
    zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
    if(zOut==0)
    {
        sqlite3_result_error_nomem(context);
        return -1;
    }
    for(index=0;index<nIn;index++)
    {
        zOut[index]=rot13c(zIn[index]);
    }
    zOut[index]=0;
    sqlite3_result_text(context,(char *)zOut,index,SQLITE_TRANSIENT);
    sqlite3_free(zToFree);
    return 0;
}

#if defined(__MD2__)|| defined(__ALL__)

static int md2(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoMd2(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__MD4__)|| defined(__ALL__)

static int md4(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoMd4(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__MD5__)|| defined(__ALL__)

static int md5(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoMd5(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__SHA1__)|| defined(__ALL__)

static int sha1(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha1 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha1(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__SHA224__)|| defined(__ALL__)

static int sha224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha224(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__SHA256__)|| defined(__ALL__)

static int sha256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha256(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__SHA384__)|| defined(__ALL__)

static int sha384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha384(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__SHA512__)|| defined(__ALL__)

static int sha512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha512(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__SHA3224__)|| defined(__ALL__)

static int sha3_224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha3_224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha3_224(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SHA3256__)|| defined(__ALL__)

static int sha3_256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha3_256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha3_256(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SHA3384__)|| defined(__ALL__)

static int sha3_384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha3_384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha3_384(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SHA3512__)|| defined(__ALL__)

static int sha3_512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Sha3_512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSha3_512(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__MD128__)|| defined(__ALL__)

static int ripemd128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("RipeMD128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoRipeMD128(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__MD160__)|| defined(__ALL__)

static int ripemd160(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("RipeMD160 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoRipeMD160(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__MD256__)|| defined(__ALL__)

static int ripemd256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("RipeMD256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoRipeMD256(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__MD320__)|| defined(__ALL__)

static int ripemd320(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("RipeMD320 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoRipeMD320(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__BLAKE2B__)|| defined(__ALL__)

static int blake2b(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Blake2b Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoBlake2b(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

#if defined(__BLAKE2S__)|| defined(__ALL__)

static int blake2s(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Blake2s Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoBlake2s(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__TIGER__)|| defined(__ALL__)

static int tiger(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Tiger Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoTiger(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SHAKE128__)|| defined(__ALL__)

static int shake128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Shake128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoShake128(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SHAKE256__)|| defined(__ALL__)

static int shake256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Shake128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoShake256(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SIPHASH64__)|| defined(__ALL__)

static int siphash64(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("SipHash64 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSipHash64(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SIPHASH128__)|| defined(__ALL__)

static int siphash128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("SipHash128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSipHash128(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__LSH224__)|| defined(__ALL__)

static int lsh224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("LSH224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoLSH224(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__LSH256__)|| defined(__ALL__)

static int lsh256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("LSH2256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoLSH256(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__LSH384__)|| defined(__ALL__)

static int lsh384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("LSH384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoLSH384(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__LSH512__)|| defined(__ALL__)

static int lsh512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("LSH512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoLSH512(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__SM3__)|| defined(__ALL__)

static int sm3(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("SM3 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugStringA("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugStringA(zIn);
          result = DoSM3(zIn);
          if(result!=NULL)
          {
              OutputDebugStringA("Result Not NULL\r\n");
              OutputDebugStringA(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugStringA("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  OutputDebugStringA("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugStringA("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugStringA("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif
#if defined(__WHIRLPOOL__)|| defined(__ALL__)

static int whirlpool(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Whirlpool Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
        OutputDebugStringA(zIn);
        result = DoWhirlpool(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);

        }
        else
        {
            OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

#endif

static int macmd2(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacMd2 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacMd2(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacMd2(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macmd4(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacMd4 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacMd4(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacMd4(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macmd5(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacMd5 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacMd5(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacMd5(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha1(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSha1 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha1(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha1(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSha224 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha224(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha224(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSha256 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha256(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha256(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSha384 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha384(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha384(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSha512 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha512(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha512(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha3224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macsha3224 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha3224(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha3224(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha3256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macsha3256 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha3256(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha3256(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha3384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macsha3384 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha3384(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha3384(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsha3512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macsha3512 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSha3512(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSha3512(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macripemd128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macripemd128 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacRipeMd128(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd128(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macripemd160(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macripemd128 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacRipeMd160(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd160(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macripemd256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macripemd256 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacRipeMd256(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd256(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macripemd320(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("Macripemd320 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2])==SQLITE_INTEGER)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacRipeMd320(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd320(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        
        
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macblake2b(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacBlake2b Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacBlake2b(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacBlake2b(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macblake2s(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacBlake2s Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacBlake2s(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacBlake2s(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int mactiger(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacTiger Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacTiger(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacTiger(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macshake128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacShake128 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacShake128(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacShake128(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macshake256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacShake256 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacShake256(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacShake256(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsiphash64(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSipHash64 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSipHash64(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSipHash64(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsiphash128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSipHash128 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSipHash128(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSipHash128(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int maclsh224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacLsh224 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacLsh224(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacLsh224(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int maclsh256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacLsh256 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacLsh256(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacLsh256(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int maclsh384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacLsh384 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacLsh384(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacLsh384(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int maclsh512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacLsh512 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacLsh512(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacLsh512(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macsm3(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacSm3 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacSm3(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacSm3(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macwhirlpool(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacWhirlpool Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacWhirlpool(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacWhirlpool(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int maccmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacCMac Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacCMac(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacCMac(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int maccbccmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacCbcCMac Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacCbcCMac(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacCbcCMac(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlen(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlen(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macdmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacDMac Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacDMac(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacDMac(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macgmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacGMac Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacGMac(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacGMac(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

// TODO: Verify HMAC
static int machmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacHMac Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacHMac(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacHMac(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlen(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macpoly1305(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacPoly1305 Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacPoly1305(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacPoly1305(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int mactwotrack(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacTwoTrack Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacTwoTrack(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacTwoTrack(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int macvmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugStringA("MacVMac Called\r\n");
    const unsigned char * zIn;
    const unsigned char * zKey;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nLength=0;
    int keyIn =0;
    int nIn = 0;
    int index=0;
    int resultLength=0;
    const char * fromHex;
    const char * result;
    
    if(argc!=3)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if ( 
        (sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1])==SQLITE_BLOB || sqlite3_value_type(argv[1])==SQLITE_TEXT)
    )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char *)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[1]);
        if(sqlite3_value_int(argv[2])== 1)
        {
            // do hconversion from hex
            fromHex= FromHexSZ(zKey,&resultLength);
            if(fromHex)
            {
                result = DoMacVMac(fromHex,resultLength,zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                OutputDebugStringA("FromHex Failed\r\n");
                return -1;
            }
        }
        else if (sqlite3_value_int(argv[2])== 0)
        {
            // dont do conversion from hex
            result = DoMacVMac(zKey,keyIn,zIn);
        }
        else
        {
            // invalid
            OutputDebugStringA("Invalid Parameter\r\n");
            return -1;
        }
        OutputDebugStringA(zKey);
        OutputDebugStringA(zIn);
        if(result!=NULL)
        {
            OutputDebugStringA("Result Not NULL\r\n");
            OutputDebugStringA(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) +1);
            if(zOut!=0)
            {
                OutputDebugStringA("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                OutputDebugStringA("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                OutputDebugStringA("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             OutputDebugStringA("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int tohex(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    const unsigned char * zIn;
    char * zOut;
    char * zToFree;
    const char * result;
    int nIn = 0;
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if(sqlite3_value_type(argv[0])==SQLITE_BLOB||sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
        if(nIn>0)
        {
            result = ToHexSZ(zIn);
            if(result)
            {
                nIn = strlength(result);
                zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
                if(zOut!=0)
                {
                    OutputDebugStringA("ZOut Not NULL\r\n");
                    strncpy_s(zOut,nIn+1,result,strlength(result));
                    OutputDebugStringA("After StrCpy\r\n");
                    sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                    sqlite3_free(zToFree);
                    
                }
                else
                {
                    OutputDebugStringA("ZOut  NULL\r\n");
                }
                FreeCryptoResult(result);
                return SQLITE_OK;
            }
            else
            {
                return -1;
            }
            
        }
        else
        {
            return -1;
        }
    }
    return SQLITE_OK;
}

static int fromhex(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    const unsigned char * zIn;
    char * zOut;
    char * zToFree;
    const char * result ;
    int resultLength=0;
    int nIn = 0;
    if(argc!=1)
    {
        OutputDebugStringA("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugStringA("Value Type is NULL\r\n");
        return -1;
    }
    else if(sqlite3_value_type(argv[0])==SQLITE_BLOB||sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        OutputDebugStringA("fromhex: sqlite_text\r\n");
        nIn = sqlite3_value_bytes(argv[0]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
        if(nIn>0)
        {
            OutputDebugStringA("fromhex: in>0\r\n");
            result = FromHexSZ(zIn,&resultLength);
            if(result)
            {
                OutputDebugStringA(result);
                nIn = resultLength;
                zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
                if(zOut!=0)
                {
                    OutputDebugStringA("ZOut Not NULL\r\n");
                    strncpy_s(zOut,nIn+1,result,strlength(result));
                    OutputDebugStringA("After StrCpy\r\n");
                    sqlite3_result_blob(context,(char *)zOut,resultLength,SQLITE_TRANSIENT);
                    sqlite3_free(zToFree);
                }
                else
                {
                    OutputDebugStringA("ZOut  NULL\r\n");
                }
                FreeCryptoResult(result);
                return SQLITE_OK;
            }
            else
            {
                OutputDebugStringA("fromhex: Failed FromHex\r\n");
                return -1;
            }
            
        }
        else
        {
            OutputDebugStringA("fromhex: nIn<=0\r\n");
            return -1;
        }
    }
    else
    {
        OutputDebugStringA("fromhex: Invalid Input\r\n");
        return -1;
    }
    return SQLITE_OK;
}



#ifdef _WIN32
__declspec(dllexport)
#endif
extern int sqlite3_hashing_init(
    sqlite3 *db, 
    char **pzErrMsg, 
    const sqlite3_api_routines *pApi
){
  int rc = SQLITE_OK;

  SQLITE_EXTENSION_INIT2(pApi);

  rc = sqlite3_create_function(db,"hash_ping",0,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, hash_ping, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"rot13",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, rot13, 0, 0);
  if ( rc != SQLITE_OK) return rc;

#if defined(__MD2__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"md2", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md2, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__MD4__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"md4", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md4, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__MD5__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"md5", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md5, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA1__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha1",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha1, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA224__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha224",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha224, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha256",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA384__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha384",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha384, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA512__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha512",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA3224__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3224",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_224, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA3256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3256",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA3384__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3384",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_384, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHA3512__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3512",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__MD128__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd128, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__MD160__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd160", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd160, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__MD256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__MD320__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd320", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd320, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__BLAKE2B__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"blake2b", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, blake2b, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__BLAKE2S__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"blake2s", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, blake2s, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__TIGER__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"tiger", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, tiger, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHAKE128__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"shake128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, shake128, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SHAKE256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"shake256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, shake256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SIPHASH64__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"siphash64", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, siphash64, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SIPHASH128__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"siphash128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, siphash128, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__LSH224__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh224", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh224, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__LSH256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__LSH384__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh384", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh384, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__LSH512__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh512", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__SM3__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sm3", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sm3, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif
#if defined(__WHIRLPOOL__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"whirlpool", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, whirlpool, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#endif

  rc = sqlite3_create_function(db,"macmd2",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macmd2, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macmd4",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macmd4, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macmd5",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macmd5, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha1",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha1, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha224",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha224, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha256",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha384",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha512",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha512, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha3224",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha3224, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha3256",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha3256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha3384",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha3384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha3384",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha3384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsha3512",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsha3512, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macripemd128",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macripemd128, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macripemd160",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macripemd160, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macripemd256",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macripemd256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macripemd320",3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macripemd320, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macblake2b", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macblake2b, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macblake2s", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macblake2s, 0, 0);
  if ( rc != SQLITE_OK) return rc;


  rc = sqlite3_create_function(db,"mactiger", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, mactiger, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macshake128", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macshake128, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macshake256", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macshake256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsiphash64", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsiphash64, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsiphash128", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsiphash128, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"maclsh224", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maclsh224, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"maclsh256", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maclsh256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"maclsh384", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maclsh384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"maclsh512", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maclsh512, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macsm3", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macsm3, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macwhirlpool", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macwhirlpool, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"maccmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maccmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"maccbccmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maccbccmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macdmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macdmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macgmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macgmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"machmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, machmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macpoly1305", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macpoly1305, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"mactwotrack", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, mactwotrack, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"macvmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macvmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"fromhex", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, fromhex, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"tohex", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, tohex, 0, 0);
  if ( rc != SQLITE_OK) return rc;


  rc = sqlite3_create_module(db,"hash_info", &hash_info_Module, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_module(db,"hash_sizes", &hash_sizes_Module, 0);
  if ( rc != SQLITE_OK) return rc;

  return rc;
}