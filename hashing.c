/* Add your header comment here */
#include <inttypes.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
#include <stdlib.h>
#include <string.h>
#define WIN32_LEAN_AND_MEAN      // Exclude rarely-used stuff from Windows headers

#include <windows.h>
#include "crypto.h"

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
    nIn = strlen(PING_MESSAGE);
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

static int md2(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoMd2(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int md4(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoMd4(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int md5(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoMd5(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int panama(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoPanama(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int des(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoDES(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int arc4(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoArc4(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int seal(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSeal(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha1(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha1 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha224(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha256(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha384(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha512(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha3_224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha3_224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha3_224(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha3_256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha3_256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha3_256(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha3_384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha3_384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha3_384(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sha3_512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Sha3_512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSha3_512(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int ripemd128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("RipeMD128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoRipeMD128(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int ripemd160(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("RipeMD160 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoRipeMD160(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int ripemd256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("RipeMD256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoRipeMD256(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int ripemd320(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("RipeMD320 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoRipeMD320(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int blake2b(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Blake2b Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoBlake2b(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int blake2s(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Blake2s Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoBlake2s(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int tiger(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Tiger Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoTiger(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int shake128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Shake128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoShake128(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int shake256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Shake128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoShake256(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int siphash64(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("SipHash64 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSipHash64(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int siphash128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("SipHash128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSipHash128(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int lsh224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("LSH224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoLSH224(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int lsh256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("LSH2256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoLSH256(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int lsh384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("LSH384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoLSH384(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int lsh512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("LSH512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoLSH512(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int sm3(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("SM3 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoSM3(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
      return -1;
    }
    return SQLITE_OK;
}

static int whirlpool(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    OutputDebugString("Whirlpool Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    const char * buffer;
    if(argc!=1)
    {
        OutputDebugString("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        OutputDebugString("Valu Type is NULL\r\n");
        return -1;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          OutputDebugString("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          OutputDebugString(zIn);
          result = DoWhirlpool(zIn);
          if(result!=NULL)
          {
              OutputDebugString("Result Not NULL\r\n");
              OutputDebugString(result);
              nIn = strlen(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  OutputDebugString("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlen(result));
                  OutputDebugString("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  OutputDebugString("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              OutputDebugString("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlen("Type Not Supported for Hashing\r\n"));
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

  rc = sqlite3_create_function(db,"md2", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md2, 0, 0);
  if ( rc != SQLITE_OK) return rc;
  
  rc = sqlite3_create_function(db,"md4", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md4, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"md5", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md5, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha1",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha1, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha224",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha224, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha256",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha384",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha512",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
  

  rc = sqlite3_create_function(db,"sha3224",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_224, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha3256",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha3384",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sha3512",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_512, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  /*
  #define algo_ripemd_128 13
#define algo_ripemd_160 14
#define algo_ripemd_256 15
#define algo_ripemd_320 16
#define algo_blake2b 17
#define algo_blake2s 18
#define algo_tiger 19
#define algo_shake_128 20
#define algo_shake_256 21
#define algo_sip_hash 22
#define algo_lsh_128 23
#define algo_lsh_256 24
#define algo_sm3 25
#define algo_whirlpool 26
  */

  rc = sqlite3_create_function(db,"ripemd128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd128, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"ripemd160", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd160, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"ripemd256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"ripemd320", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd320, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"blake2b", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, blake2b, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"blake2s", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, blake2s, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"tiger", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, tiger, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"shake128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, shake128, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"shake256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, shake256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"siphash64", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, siphash64, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"siphash128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, siphash128, 0, 0);
  if ( rc != SQLITE_OK) return rc;


  rc = sqlite3_create_function(db,"lsh224", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh224, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"lsh256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"lsh384", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh384, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"lsh512", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh512, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"sm3", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sm3, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"whirlpool", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, whirlpool, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"panama", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, panama, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"des", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, des, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"arc4", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, arc4, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"seal", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, seal, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_module(db,"hash_info", &hash_info_Module, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_module(db,"hash_sizes", &hash_sizes_Module, 0);
  if ( rc != SQLITE_OK) return rc;

  return rc;
}