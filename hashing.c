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
#include "crypto_blob.h"
#include "crypto_mac.h"
#include "crypto_mac_blob.h"

SQLITE_EXTENSION_INIT1
#include "blob_hashing.h"
#include "hashsizes.h"
#include "hashinfo.h"

#include <stdio.h>



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
    if(sqlite3_value_type(argv[0])==SQLITE_NULL) return SQLITE_ERROR;
    zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
    nIn = sqlite3_value_bytes(argv[0]);
    zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
    if(zOut==0)
    {
        sqlite3_result_error_nomem(context);
        return SQLITE_ERROR;
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
    DebugMessage("Md2 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoMd2(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#if defined(__USE_BLOB__)
static int md2blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db=NULL;
    Md2BlobContextPtr md2BlobContext;
    
    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result=NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Md2Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                md2BlobContext = Md2Initialize();
                if (md2BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md2Update(md2BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Md2Finalize(md2BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macmd2(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacMd2 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        sqlite3_result_error(context, "Incorrect number of arguments", strlength("Incorrect number of arguments"));
        return SQLITE_ERROR;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        sqlite3_result_error(context, "Value type is null", strlength("Value type is null"));
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacMd2(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacMd2(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macmd2blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Md2MacBlobContextPtr md2MacBlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;
    const unsigned char* zKey;
    const char* fromHex;
    int nLength = 0;
    int resultLength = 0;
    int keyIn = 0;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Md2MacBlob Called\r\n");
    if (argc != 6)
    {
        DebugMessage("Test\r\n");
        sqlite3_result_error(context,"Invalid arguments",strlength("Invalid arguments"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER &&// rowid
        sqlite3_value_type(argv[4]) == SQLITE_TEXT &&// key
        sqlite3_value_type(argv[5]) == SQLITE_INTEGER // hex or not
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        keyIn = sqlite3_value_bytes(argv[4]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[4]);
        

        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                if (sqlite3_value_int(argv[5]) == 1)
                {
                    // do hconversion from hex
                    fromHex = FromHexSZ(zKey, &resultLength);
                    if (fromHex)
                    {
                        md2MacBlobContext = Md2MacInitialize(fromHex, resultLength);
                        if (md2MacBlobContext != NULL)
                        {
                            while (rc == SQLITE_OK && remainingSize > 0)
                            {
                                length = MIN(buffer_size, remainingSize);
                                rc = sqlite3_blob_read(blob, buffer, length, offset);
                                if (rc == SQLITE_OK)
                                {
                                    Md2MacUpdate(md2MacBlobContext, buffer, length);
                                    offset += length;
                                    remainingSize -= length;
                                }
                            }
                            if (rc == SQLITE_OK)
                            {
                                result = Md2MacFinalize(md2MacBlobContext);
                                if (result != NULL)
                                {
                                    nIn = strlength(result);
                                    zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                                    if (zOut != 0)
                                    {
                                        DebugMessage("ZOut Not NULL\r\n");
                                        strncpy_s(zOut, nIn + 1, result, strlength(result));
                                        DebugMessage("After StrCpy\r\n");
                                        sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                        sqlite3_free(zToFree);
                                        rc = SQLITE_OK;
                                    }
                                    else
                                    {
                                        DebugMessage("ZOut  NULL\r\n");
                                        rc = SQLITE_ERROR;
                                    }
                                }
                                else
                                {
                                    sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                                    rc = SQLITE_ERROR;
                                }
                            }
                            else
                            {
                                sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                            rc = SQLITE_ERROR;
                        }
                        FreeCryptoResult((void*)fromHex);
                    }
                    else
                    {
                        DebugMessage("FromHex Failed\r\n");
                        return SQLITE_ERROR;
                    }
                }
                else if (sqlite3_value_int(argv[5]) == 0)
                {
                    // dont do conversion from hex
                    md2MacBlobContext = Md2MacInitialize(zKey, keyIn);
                    if (md2MacBlobContext != NULL)
                    {
                        while (rc == SQLITE_OK && remainingSize > 0)
                        {
                            length = MIN(buffer_size, remainingSize);
                            rc = sqlite3_blob_read(blob, buffer, length, offset);
                            if (rc == SQLITE_OK)
                            {
                                Md2MacUpdate(md2MacBlobContext, buffer, length);
                                offset += length;
                                remainingSize -= length;
                            }
                        }
                        if (rc == SQLITE_OK)
                        {
                            result = Md2MacFinalize(md2MacBlobContext);
                            if (result != NULL)
                            {
                                nIn = strlength(result);
                                zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                                if (zOut != 0)
                                {
                                    DebugMessage("ZOut Not NULL\r\n");
                                    strncpy_s(zOut, nIn + 1, result, strlength(result));
                                    DebugMessage("After StrCpy\r\n");
                                    sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                    sqlite3_free(zToFree);
                                    rc = SQLITE_OK;
                                }
                                else
                                {
                                    DebugMessage("ZOut  NULL\r\n");
                                    rc = SQLITE_ERROR;
                                }
                            }
                            else
                            {
                                sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    // invalid
                    DebugMessage("Invalid Parameter\r\n");
                    return SQLITE_ERROR;
                }
                
                free(buffer);
            }
            sqlite3_blob_close(blob);
        
        }
        else
        {
            sqlite3_result_error(context, "Failed to open the blob object\r\n",strlength("Failed to open the blob object\r\n"));
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#endif

#if defined(__MD4__)|| defined(__ALL__)

static int md4(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Md4 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoMd4(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#if defined(__USE_BLOB__)
static int md4blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db=NULL;
    Md4BlobContextPtr md4BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Md4Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                md4BlobContext = Md4Initialize();
                if (md4BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md4Update(md4BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Md4Finalize(md4BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macmd4(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacMd4 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacMd4(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacMd4(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macmd4blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Md4MacBlobContextPtr md4MacBlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;
    const unsigned char* zKey;
    const char* fromHex;
    int nLength = 0;
    int resultLength = 0;
    int keyIn = 0;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Md2MacBlob Called\r\n");
    if (argc != 6)
    {
        DebugMessage("Test\r\n");
        sqlite3_result_error(context, "Invalid arguments", strlength("Invalid arguments"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER &&// rowid
        sqlite3_value_type(argv[4]) == SQLITE_TEXT &&// key
        sqlite3_value_type(argv[5]) == SQLITE_INTEGER // hex or not
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        keyIn = sqlite3_value_bytes(argv[4]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[4]);


        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                if (sqlite3_value_int(argv[5]) == 1)
                {
                    // do hconversion from hex
                    fromHex = FromHexSZ(zKey, &resultLength);
                    if (fromHex)
                    {
                        md4MacBlobContext = Md4MacInitialize(fromHex, resultLength);
                        if (md4MacBlobContext != NULL)
                        {
                            while (rc == SQLITE_OK && remainingSize > 0)
                            {
                                length = MIN(buffer_size, remainingSize);
                                rc = sqlite3_blob_read(blob, buffer, length, offset);
                                if (rc == SQLITE_OK)
                                {
                                    Md4MacUpdate(md4MacBlobContext, buffer, length);
                                    offset += length;
                                    remainingSize -= length;
                                }
                            }
                            if (rc == SQLITE_OK)
                            {
                                result = Md4MacFinalize(md4MacBlobContext);
                                if (result != NULL)
                                {
                                    nIn = strlength(result);
                                    zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                                    if (zOut != 0)
                                    {
                                        DebugMessage("ZOut Not NULL\r\n");
                                        strncpy_s(zOut, nIn + 1, result, strlength(result));
                                        DebugMessage("After StrCpy\r\n");
                                        sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                        sqlite3_free(zToFree);
                                        rc = SQLITE_OK;
                                    }
                                    else
                                    {
                                        DebugMessage("ZOut  NULL\r\n");
                                        rc = SQLITE_ERROR;
                                    }
                                }
                                else
                                {
                                    sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                                    rc = SQLITE_ERROR;
                                }
                            }
                            else
                            {
                                sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                            rc = SQLITE_ERROR;
                        }
                        FreeCryptoResult((void*)fromHex);
                    }
                    else
                    {
                        DebugMessage("FromHex Failed\r\n");
                        return SQLITE_ERROR;
                    }
                }
                else if (sqlite3_value_int(argv[5]) == 0)
                {
                    // dont do conversion from hex
                    md4MacBlobContext = Md4MacInitialize(zKey, keyIn);
                    if (md4MacBlobContext != NULL)
                    {
                        while (rc == SQLITE_OK && remainingSize > 0)
                        {
                            length = MIN(buffer_size, remainingSize);
                            rc = sqlite3_blob_read(blob, buffer, length, offset);
                            if (rc == SQLITE_OK)
                            {
                                Md4MacUpdate(md4MacBlobContext, buffer, length);
                                offset += length;
                                remainingSize -= length;
                            }
                        }
                        if (rc == SQLITE_OK)
                        {
                            result = Md4MacFinalize(md4MacBlobContext);
                            if (result != NULL)
                            {
                                nIn = strlength(result);
                                zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                                if (zOut != 0)
                                {
                                    DebugMessage("ZOut Not NULL\r\n");
                                    strncpy_s(zOut, nIn + 1, result, strlength(result));
                                    DebugMessage("After StrCpy\r\n");
                                    sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                    sqlite3_free(zToFree);
                                    rc = SQLITE_OK;
                                }
                                else
                                {
                                    DebugMessage("ZOut  NULL\r\n");
                                    rc = SQLITE_ERROR;
                                }
                            }
                            else
                            {
                                sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    // invalid
                    DebugMessage("Invalid Parameter\r\n");
                    return SQLITE_ERROR;
                }

                free(buffer);
            }
            sqlite3_blob_close(blob);

        }
        else
        {
            sqlite3_result_error(context, "Failed to open the blob object\r\n", strlength("Failed to open the blob object\r\n"));
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif

#endif

#if defined(__MD5__)|| defined(__ALL__)

static int md5(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Md5 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoMd5(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#if defined(__USE_BLOB__)
static int md5blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db=NULL;
    Md5BlobContextPtr md5BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;
    
    db = sqlite3_context_db_handle(context);

    DebugMessage("Md5Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                md5BlobContext = Md5Initialize();
                if (md5BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md5Update(md5BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Md5Finalize(md5BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macmd5(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacMd5 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacMd5(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacMd5(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macmd5blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacM5Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif

#endif

#if defined(__SHA1__)|| defined(__ALL__)

static int sha1(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha1 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha1(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha1blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha1BlobContextPtr sha1BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha1Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha1BlobContext = Sha1Initialize();
                if (sha1BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha1Update(sha1BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha1Finalize(sha1BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macsha1(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSha1 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha1(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha1(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha1blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSha1Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if defined(__SHA224__)|| defined(__ALL__)

static int sha224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha224(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha224blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha224BlobContextPtr sha224BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha224Blob Called\r\n");
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid Arguments\r\n", strlength("Invalid Arguments\r\n"));
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha224BlobContext = Sha224Initialize();
                if (sha224BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha224Update(sha224BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha224Finalize(sha224BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if (__USE_MAC__)
static int macsha224(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSha224 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha224(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha224(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha224blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Macssh224Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if defined(__SHA256__)|| defined(__ALL__)

static int sha256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha256(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha256BlobContextPtr sha256BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha256Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha256BlobContext = Sha256Initialize();
                if (sha256BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha256Update(sha256BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha256Finalize(sha256BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macsha256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSha256 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha256(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha256(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Macsha256Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if defined(__SHA384__)|| defined(__ALL__)

static int sha384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha384(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha384blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha384BlobContextPtr sha384BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha384Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha384BlobContext = Sha384Initialize();
                if (sha384BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha384Update(sha384BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha384Finalize(sha384BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macsha384(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSha384 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha384(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha384(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}


#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha384blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Macsha384Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if defined(__SHA512__)|| defined(__ALL__)

static int sha512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha512(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha512blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha512BlobContextPtr sha512BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha512Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha512BlobContext = Sha512Initialize();
                if (sha512BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha512Update(sha512BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha512Finalize(sha512BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macsha512(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSha512 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha512(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha512(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}


#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha512blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Macsha512Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif


#endif

#if defined(__SHA3224__)|| defined(__ALL__)

static int sha3224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha3_224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha3_224(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha3224blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha3224BlobContextPtr sha3224BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha3224Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha3224BlobContext = Sha3224Initialize();
                if (sha3224BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha3224Update(sha3224BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha3224Finalize(sha3224BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macsha3224(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macsha3224 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha3224(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha3224(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha3224blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Macsha3224blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SHA3256__)|| defined(__ALL__)

static int sha3_256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha3_256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha3_256(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha3256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha3256BlobContextPtr sha3256BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha3256Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha3256BlobContext = Sha3256Initialize();
                if (sha3256BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha3256Update(sha3256BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha3256Finalize(sha3256BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macsha3256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macsha3256 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha3256(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha3256(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha3256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSha3256Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SHA3384__)|| defined(__ALL__)

static int sha3_384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha3_384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha3_384(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha3384blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha3384BlobContextPtr sha3384BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha3384Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha3384BlobContext = Sha3384Initialize();
                if (sha3384BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha3384Update(sha3384BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha3384Finalize(sha3384BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macsha3384(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macsha3384 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha3384(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha3384(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha3384blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSha3384Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SHA3512__)|| defined(__ALL__)

static int sha3_512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Sha3_512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSha3_512(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
              return SQLITE_ERROR;
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sha3512blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sha3512BlobContextPtr sha3512BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sha3512Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sha3512BlobContext = Sha3512Initialize();
                if (sha3512BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sha3512Update(sha3512BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sha3512Finalize(sha3512BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macsha3512(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macsha3512 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSha3512(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSha3512(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsha3512blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSha3512Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__RIPEMD128__)|| defined(__ALL__)

static int ripemd128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("RipeMD128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoRipeMD128(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int ripemd128blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    RipeMD128BlobContextPtr ripemd128BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("RipeMD128Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                ripemd128BlobContext = RipeMD128Initialize();
                if (ripemd128BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            RipeMD128Update(ripemd128BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = RipeMD128Finalize(ripemd128BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macripemd128(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macripemd128 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacRipeMd128(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd128(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macripemd128blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacRipe128Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__RIPEMD160__)|| defined(__ALL__)

static int ripemd160(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("RipeMD160 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoRipeMD160(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int ripemd160blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    RipeMD160BlobContextPtr ripemd160BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("RipeMD160Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                ripemd160BlobContext = RipeMD160Initialize();
                if (ripemd160BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            RipeMD160Update(ripemd160BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = RipeMD160Finalize(ripemd160BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macripemd160(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macripemd128 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacRipeMd160(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd160(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macripemd160blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacRipeMD160blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__RIPEMD256__)|| defined(__ALL__)

static int ripemd256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("RipeMD256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoRipeMD256(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int ripemd256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    RipeMD256BlobContextPtr ripemd256BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("RipeMD256Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                ripemd256BlobContext = RipeMD256Initialize();
                if (ripemd256BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            RipeMD256Update(ripemd256BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = RipeMD256Finalize(ripemd256BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int macripemd256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macripemd256 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacRipeMd256(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd256(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macripemd256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacRipeMD256Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__RIPEMD320__)|| defined(__ALL__)

static int ripemd320(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("RipeMD320 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoRipeMD320(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int ripemd320blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    RipeMD320BlobContextPtr ripemd320BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("RipeMD320Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                ripemd320BlobContext = RipeMD320Initialize();
                if (ripemd320BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            RipeMD320Update(ripemd320BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = RipeMD320Finalize(ripemd320BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macripemd320(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Macripemd320 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[2]) == SQLITE_INTEGER)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacRipeMd320(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacRipeMd320(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);


        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macripemd320blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacRipeMD320Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__BLAKE2B__)|| defined(__ALL__)

static int blake2b(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Blake2b Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoBlake2b(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int blake2bblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Blake2BBlobContextPtr blake2bBlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Blake2BBlob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                blake2bBlobContext = Blake2BInitialize();
                if (blake2bBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Blake2BUpdate(blake2bBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Blake2BFinalize(blake2bBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if(__USE_MAC__)
static int macblake2b(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacBlake2b Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacBlake2b(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacBlake2b(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macblake2bblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacBlake2BBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif

#endif

#if defined(__BLAKE2S__)|| defined(__ALL__)

static int blake2s(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Blake2s Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoBlake2s(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int blake2sblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Blake2SBlobContextPtr blake2sBlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Blake2SBlob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                blake2sBlobContext = Blake2SInitialize();
                if (blake2sBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Blake2SUpdate(blake2sBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Blake2SFinalize(blake2sBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macblake2s(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacBlake2s Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacBlake2s(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacBlake2s(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macblake2sblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacBlake2SBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__TIGER__)|| defined(__ALL__)

static int tiger(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Tiger Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoTiger(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int tigerblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    TigerBlobContextPtr tigerBlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("TigerBlob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                tigerBlobContext = TigerInitialize();
                if (tigerBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            TigerUpdate(tigerBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = TigerFinalize(tigerBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int mactiger(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacTiger Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacTiger(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacTiger(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int mactigerblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacTigerBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SHAKE128__)|| defined(__ALL__)

static int shake128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Shake128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoShake128(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int shake128blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Shake128BlobContextPtr shake128BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Shake128Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                shake128BlobContext = Shake128Initialize();
                if (shake128BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Shake128Update(shake128BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Shake128Finalize(shake128BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macshake128(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacShake128 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacShake128(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacShake128(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macshake128blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacShake128Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SHAKE256__)|| defined(__ALL__)

static int shake256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Shake128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoShake256(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int shake256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Shake256BlobContextPtr shake256BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Shake256Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                shake256BlobContext = Shake256Initialize();
                if (shake256BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Shake256Update(shake256BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Shake256Finalize(shake256BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macshake256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacShake256 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;
    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacShake256(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacShake256(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macshake256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacShake256Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SIPHASH64__)|| defined(__ALL__)

static int siphash64(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("SipHash64 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSipHash64(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int siphash64blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Siphash64BlobContextPtr siphash64BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Siphash64Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                siphash64BlobContext = Siphash64Initialize();
                if (siphash64BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Siphash64Update(siphash64BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Siphash64Finalize(siphash64BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macsiphash64(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSipHash64 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;
    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSipHash64(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSipHash64(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsiphash64blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSipHash64Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SIPHASH128__)|| defined(__ALL__)

static int siphash128(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("SipHash128 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSipHash128(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int siphash128blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Siphash128BlobContextPtr siphash128BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Siphash128Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                siphash128BlobContext = Siphash128Initialize();
                if (siphash128BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Siphash128Update(siphash128BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Siphash128Finalize(siphash128BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int macsiphash128(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSipHash128 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;
    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSipHash128(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSipHash128(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsiphash128blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSipHash128Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__LSH224__)|| defined(__ALL__)

static int lsh224(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("LSH224 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoLSH224(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int lsh224blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Lsh224BlobContextPtr lsh224BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Lsh224Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                lsh224BlobContext = Lsh224Initialize();
                if (lsh224BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Lsh224Update(lsh224BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Lsh224Finalize(lsh224BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int maclsh224(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacLsh224 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacLsh224(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacLsh224(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}


#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int maclsh224blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacLSH224Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__LSH256__)|| defined(__ALL__)

static int lsh256(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("LSH2256 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoLSH256(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int lsh256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Lsh256BlobContextPtr lsh256BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Lsh256Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                lsh256BlobContext = Lsh256Initialize();
                if (lsh256BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Lsh256Update(lsh256BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Lsh256Finalize(lsh256BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int maclsh256(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacLsh256 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacLsh256(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacLsh256(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int maclsh256blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacLSH256Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__LSH384__)|| defined(__ALL__)

static int lsh384(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("LSH384 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoLSH384(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int lsh384blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Lsh384BlobContextPtr lsh384BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Lsh384Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                lsh384BlobContext = Lsh384Initialize();
                if (lsh384BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Lsh384Update(lsh384BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Lsh384Finalize(lsh384BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)
static int maclsh384(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacLsh384 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacLsh384(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacLsh384(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int maclsh384blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacLSH384Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__LSH512__)|| defined(__ALL__)

static int lsh512(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("LSH512 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoLSH512(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int lsh512blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Lsh512BlobContextPtr lsh512BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Lsh512Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                lsh512BlobContext = Lsh512Initialize();
                if (lsh512BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Lsh512Update(lsh512BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Lsh512Finalize(lsh512BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif
#if defined(__USE_MAC__)
static int maclsh512(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacLsh512 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacLsh512(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacLsh512(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int maclsh512blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacLSH512Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__SM3__)|| defined(__ALL__)

static int sm3(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("SM3 Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        
          DebugMessage("Non Buffered Read\r\n");
          zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
          DebugMessage(zIn);
          result = DoSM3(zIn);
          if(result!=NULL)
          {
              DebugMessage("Result Not NULL\r\n");
              DebugMessage(result);
              nIn = strlength(result);
              zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
              if(zOut!=0)
              {
                  DebugMessage("ZOut Not NULL\r\n");
                  strncpy_s(zOut,nIn+1,result,strlength(result));
                  DebugMessage("After StrCpy\r\n");
                  sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                  sqlite3_free(zToFree);
                  
              }
              else
              {
                  DebugMessage("ZOut  NULL\r\n");
              }
              FreeCryptoResult(result);

          }
          else
          {
              DebugMessage("Result is NULL\r\n");
          }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int sm3blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    Sm3BlobContextPtr sm3BlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("Sm3Blob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                sm3BlobContext = Sm3Initialize();
                if (sm3BlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Sm3Update(sm3BlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = Sm3Finalize(sm3BlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macsm3(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacSm3 Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacSm3(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacSm3(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}


#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macsm3blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacSM3Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif
#if defined(__WHIRLPOOL__)|| defined(__ALL__)

static int whirlpool(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("Whirlpool Called\r\n");
    const unsigned char * zIn;
    unsigned char * zOut;
    unsigned char * zToFree;
    int nIn = 0;
    int index=0;
    const char * result;
    
    if(argc!=1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if ( sqlite3_value_type(argv[0])==SQLITE_BLOB || sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
        DebugMessage(zIn);
        result = DoWhirlpool(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            nIn = strlength(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut,nIn+1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
                
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);

        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_BLOB__)
static int whirlpoolblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;
    WhirlpoolBlobContextPtr whirlpoolBlobContext;

    const unsigned char* zIn;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nIn = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    int position = 0;
    int rc = 0;
    int offset = 0;
    int length = 0;
    unsigned int index = 0;
    unsigned int outputCount = 0;
    unsigned int buffer_size = 0;
    const char* result = NULL;
    const char* database;
    const char* table;
    const char* column;
    int64_t rowId = 0;
    sqlite3_int64 rowid;
    char* buffer = NULL;
    sqlite3_blob* blob;

    db = sqlite3_context_db_handle(context);

    DebugMessage("WhirlpoolBlob Called\r\n");
    if (argc != 4)
    {
        DebugMessage("Test\r\n");
        return SQLITE_ERROR;
    }
    if (
        sqlite3_value_type(argv[0]) == SQLITE_TEXT && // database
        sqlite3_value_type(argv[1]) == SQLITE_TEXT && // table 
        sqlite3_value_type(argv[2]) == SQLITE_TEXT && // column
        sqlite3_value_type(argv[3]) == SQLITE_INTEGER // rowid
        )
    {
        database = sqlite3_value_text(argv[0]);
        buffer_size = get_schema_page_size(context, db, database, sqlite3_value_bytes(argv[0]));
        table = sqlite3_value_text(argv[1]);
        column = sqlite3_value_text(argv[2]);
        rowid = sqlite3_value_int64(argv[3]);
        rc = sqlite3_blob_open(db, database, table, column, rowid, 0, &blob);
        if (rc == SQLITE_OK)
        {
            nBlobTextSize = sqlite3_blob_bytes(blob);
            remainingSize = nBlobTextSize;
            buffer = (char*)malloc(buffer_size);
            if (buffer != NULL)
            {
                whirlpoolBlobContext = WhirlpoolInitialize();
                if (whirlpoolBlobContext != NULL)
                {
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            WhirlpoolUpdate(whirlpoolBlobContext, buffer, length);
                            offset += length;
                            remainingSize -= length;
                        }
                    }
                    if (rc == SQLITE_OK)
                    {
                        result = WhirlpoolFinalize(whirlpoolBlobContext);
                        if (result != NULL)
                        {
                            nIn = strlength(result);
                            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                            if (zOut != 0)
                            {
                                DebugMessage("ZOut Not NULL\r\n");
                                strncpy_s(zOut, nIn + 1, result, strlength(result));
                                DebugMessage("After StrCpy\r\n");
                                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                                sqlite3_free(zToFree);
                                rc = SQLITE_OK;
                            }
                            else
                            {
                                DebugMessage("ZOut  NULL\r\n");
                                rc = SQLITE_ERROR;
                            }
                        }
                        else
                        {
                            sqlite3_result_error(context, "Failed to run Finalize\r\n", strlength("Failed to run Finalize\r\n"));
                            rc = SQLITE_ERROR;
                        }
                    }
                    else
                    {
                        sqlite3_result_error(context, "Failed to run hash\r\n", strlength("Failed to run hash\r\n"));
                        rc = SQLITE_ERROR;
                    }
                }
                else
                {
                    sqlite3_result_error(context, "Failed to allocate blobContext\r\n", strlength("Failed to allocate blobContext\r\n"));
                    rc = SQLITE_ERROR;
                }
                free(buffer);
            }
            sqlite3_blob_close(blob);
        }
        return rc;
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#endif

#if defined(__USE_MAC__)

static int macwhirlpool(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("MacWhirlpool Called\r\n");
    const unsigned char* zIn;
    const unsigned char* zKey;
    unsigned char* zOut;
    unsigned char* zToFree;
    int nLength = 0;
    int keyIn = 0;
    int nIn = 0;
    int index = 0;
    int resultLength = 0;
    const char* fromHex;
    const char* result;

    if (argc != 3)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (
        (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT) &&
        (sqlite3_value_type(argv[1]) == SQLITE_BLOB || sqlite3_value_type(argv[1]) == SQLITE_TEXT)
        )
    {
        keyIn = sqlite3_value_bytes(argv[0]);
        zKey = (const unsigned char*)sqlite3_value_text(argv[0]);
        nIn = sqlite3_value_bytes(argv[1]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[1]);
        if (sqlite3_value_int(argv[2]) == 1)
        {
            // do hconversion from hex
            fromHex = FromHexSZ(zKey, &resultLength);
            if (fromHex)
            {
                result = DoMacWhirlpool(fromHex, resultLength, zIn);
                FreeCryptoResult((void*)fromHex);
            }
            else
            {
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
            }
        }
        else if (sqlite3_value_int(argv[2]) == 0)
        {
            // dont do conversion from hex
            result = DoMacWhirlpool(zKey, keyIn, zIn);
        }
        else
        {
            // invalid
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if (result != NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
            if (zOut != 0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, nIn + 1, result, strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
            DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
        sqlite3_result_error(context, "Type Not Supported for Hashing\r\n", strlength("Type Not Supported for Hashing\r\n"));
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}


#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macwhirlpoolblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacWhirlpoolBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__CMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int maccmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacCMac Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int maccmacblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacCMacBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int maccbccmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacCbcCMac Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlen(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlen(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int maccbcmacblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacCBCMacBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__DMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int macdmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacDMac Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macdmacblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacDMacBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__GMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int macgmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacGMac Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macgmacblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacGMacBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__HMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
// TODO: Verify HMAC
static int machmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacHMac Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlen(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int machmacblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacHMacBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__POLY1305__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int macpoly1305(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacPoly1305 Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macpoly1305blob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacPoly1305Blob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__TWOTRACK__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int mactwotrack(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacTwoTrack Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) + 1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int mactwotrackblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacTwoTrackBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

#if (defined(__VMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)

static int macvmac(
    sqlite3_context *context,
    int argc,
    sqlite3_value **argv
)
{
    DebugMessage("MacVMac Called\r\n");
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                DebugMessage("FromHex Failed\r\n");
                return SQLITE_ERROR;
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
            DebugMessage("Invalid Parameter\r\n");
            return SQLITE_ERROR;
        }
        DebugMessage(zKey);
        DebugMessage(zIn);
        if(result!=NULL)
        {
            DebugMessage("Result Not NULL\r\n");
            DebugMessage(result);
            zOut = zToFree = ( unsigned char *) sqlite3_malloc64(strlength(result) +1);
            if(zOut!=0)
            {
                DebugMessage("ZOut Not NULL\r\n");
                strncpy_s(zOut, strlength(result) +1,result,strlength(result));
                DebugMessage("After StrCpy\r\n");
                sqlite3_result_text(context,(char *)zOut, strlength(result),SQLITE_TRANSIENT);
                sqlite3_free(zToFree);
            }
            else
            {
                DebugMessage("ZOut  NULL\r\n");
            }
            FreeCryptoResult(result);
        }
        else
        {
             DebugMessage("Result is NULL\r\n");
        }
    }
    else
    {
      sqlite3_result_error(context,"Type Not Supported for Hashing\r\n",strlength("Type Not Supported for Hashing\r\n"));
      return SQLITE_ERROR;
    }
    return SQLITE_OK;
}
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
static int macvmavblob(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    sqlite3* db = NULL;

    db = sqlite3_context_db_handle(context);

    DebugMessage("MacVMacBlob Called\r\n");

    sqlite3_result_error(context, "Not Implemented", strlen("Not Implemented"));
    return SQLITE_ERROR;
}
#endif
#endif

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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
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
                    DebugMessage("ZOut Not NULL\r\n");
                    strncpy_s(zOut,nIn+1,result,strlength(result));
                    DebugMessage("After StrCpy\r\n");
                    sqlite3_result_text(context,(char *)zOut,nIn,SQLITE_TRANSIENT);
                    sqlite3_free(zToFree);
                    
                }
                else
                {
                    DebugMessage("ZOut  NULL\r\n");
                }
                FreeCryptoResult(result);
                return SQLITE_OK;
            }
            else
            {
                return SQLITE_ERROR;
            }
            
        }
        else
        {
            return SQLITE_ERROR;
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
        DebugMessage("Test\r\n");
        return-1;
    }
    if(sqlite3_value_type(argv[0])==SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if(sqlite3_value_type(argv[0])==SQLITE_BLOB||sqlite3_value_type(argv[0])==SQLITE_TEXT)
    {
        DebugMessage("fromhex: sqlite_text\r\n");
        nIn = sqlite3_value_bytes(argv[0]);
        zIn = (const unsigned char *)sqlite3_value_text(argv[0]);
        if(nIn>0)
        {
            DebugMessage("fromhex: in>0\r\n");
            result = FromHexSZ(zIn,&resultLength);
            if(result)
            {
                DebugMessage(result);
                nIn = resultLength;
                zOut = zToFree = ( unsigned char *) sqlite3_malloc64(nIn+1);
                if(zOut!=0)
                {
                    DebugMessage("ZOut Not NULL\r\n");
                    strncpy_s(zOut,nIn+1,result,strlength(result));
                    DebugMessage("After StrCpy\r\n");
                    sqlite3_result_blob(context,(char *)zOut,resultLength,SQLITE_TRANSIENT);
                    sqlite3_free(zToFree);
                }
                else
                {
                    DebugMessage("ZOut  NULL\r\n");
                }
                FreeCryptoResult(result);
                return SQLITE_OK;
            }
            else
            {
                DebugMessage("fromhex: Failed FromHex\r\n");
                return SQLITE_ERROR;
            }
            
        }
        else
        {
            DebugMessage("fromhex: nIn<=0\r\n");
            return SQLITE_ERROR;
        }
    }
    else
    {
        DebugMessage("fromhex: Invalid Input\r\n");
        return SQLITE_ERROR;
    }
    return SQLITE_OK;
}

static int tobase2(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    const unsigned char* zIn;
    char* zOut;
    char* zToFree;
    const char* result;
    int nIn = 0;
    if (argc != 1)
    {
        DebugMessage("Test\r\n");
        return-1;
    }
    if (sqlite3_value_type(argv[0]) == SQLITE_NULL)
    {
        DebugMessage("Value Type is NULL\r\n");
        return SQLITE_ERROR;
    }
    else if (sqlite3_value_type(argv[0]) == SQLITE_BLOB || sqlite3_value_type(argv[0]) == SQLITE_TEXT)
    {
        nIn = sqlite3_value_bytes(argv[0]);
        zIn = (const unsigned char*)sqlite3_value_text(argv[0]);
        if (nIn > 0)
        {
            result = ToHexSZ(zIn);
            if (result)
            {
                nIn = strlength(result);
                zOut = zToFree = (unsigned char*)sqlite3_malloc64(nIn + 1);
                if (zOut != 0)
                {
                    DebugMessage("ZOut Not NULL\r\n");
                    strncpy_s(zOut, nIn + 1, result, strlength(result));
                    DebugMessage("After StrCpy\r\n");
                    sqlite3_result_text(context, (char*)zOut, nIn, SQLITE_TRANSIENT);
                    sqlite3_free(zToFree);
                }
                else
                {
                    DebugMessage("ZOut  NULL\r\n");
                }
                FreeCryptoResult(result);
                return SQLITE_OK;
            }
            else
            {
                return SQLITE_ERROR;
            }

        }
        else
        {
            return SQLITE_ERROR;
        }
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
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "md2blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, md2blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macmd2", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macmd2, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macmd2blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macmd2blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__MD4__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"md4", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md4, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "md4blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, md4blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macmd4", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macmd4, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)&& defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macmd4blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macmd4blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__MD5__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"md5", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, md5, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "md5blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, md5blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macmd5", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macmd5, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)&& defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macmd5blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macmd5blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif

#endif
#if defined(__SHA1__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha1",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha1, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha1blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha1blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha1", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha1, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)&&defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha1blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha1blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif

#endif
#if defined(__SHA224__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha224",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha224, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha224blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha224blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha224", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha224, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)&&defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha224blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha224blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha256",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha256blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha256", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha256, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha256blob",6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA384__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha384",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha384, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha384blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha384blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha384", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha384, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha384blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha384blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA512__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha512",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha512blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha512blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha512", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha512, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha512blob",6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha512blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA3224__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3224",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3224, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha3224blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha3224blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha3224", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3224, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) &&  defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha3224blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3224blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA3256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3256",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha3256blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha3256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha3256", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3256, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha3256blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA3384__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3384",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_384, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha3384blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha3384blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha3384", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3384, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha3384blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3384blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHA3512__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sha3512",1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sha3_512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sha3512blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sha3512blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsha3512", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3512, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsha3512blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsha3512blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__RIPEMD128__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd128, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "ripemd128blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, ripemd128blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macripemd128", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd128, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macripemd128blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd128blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__RIPEMD160__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd160", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd160, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "ripemd160blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, ripemd160blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macripemd160", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd160, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macripemd160blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd160blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__RIPEMD256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd256, 0, 0);
  if ( rc != SQLITE_OK) return rc;

#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "ripemd256blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, ripemd256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macripemd256", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd256, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macripemd256blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__RIPEMD320__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"ripemd320", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, ripemd320, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "ripemd320blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, ripemd320blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macripemd320", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd320, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macripemd320blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macripemd320blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__BLAKE2B__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"blake2b", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, blake2b, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "blake2bblob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, blake2bblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macblake2b", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macblake2b, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macblake2bblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macblake2bblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__BLAKE2S__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"blake2s", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, blake2s, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "blake2sblob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, blake2sblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macblake2s", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macblake2s, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macblake2sblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macblake2sblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__TIGER__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"tiger", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, tiger, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "tigerblob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, tigerblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "mactiger", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, mactiger, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "mactigerblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, mactigerblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHAKE128__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"shake128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, shake128, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "shake128blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, shake128blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macshake128", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macshake128, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macshake128blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macshake128blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SHAKE256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"shake256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, shake256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "shake256blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, shake256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macshake256", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macshake256, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macshake256blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macshake256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SIPHASH64__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"siphash64", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, siphash64, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "siphash64blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, siphash64blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsiphash64", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsiphash64, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsiphash64blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsiphash64blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SIPHASH128__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"siphash128", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, siphash128, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "siphash128blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, siphash128blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsiphash128", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsiphash128, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsiphash128blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsiphash128blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__LSH224__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh224", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh224, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "lsh224blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, lsh224blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
 #if defined(__USE_MAC__)
      rc = sqlite3_create_function(db, "maclsh224", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh224, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined ( __USE_BLOB__ )
  rc = sqlite3_create_function(db, "maclsh224blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh224blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__LSH256__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh256", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh256, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "lsh256blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, lsh256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "maclsh256", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh256, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "maclsh256blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh256blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__LSH384__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh384", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh384, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "lsh384blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, lsh384blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "maclsh384", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh384, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)&& defined ( __USE_BLOB__ )
  rc = sqlite3_create_function(db, "maclsh384blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh384blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__LSH512__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"lsh512", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, lsh512, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "lsh512blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, lsh512blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "maclsh512", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh512, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "maclsh512blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maclsh512blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__SM3__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"sm3", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, sm3, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "sm3blob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, sm3blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macsm3", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsm3, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macsm3blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macsm3blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if defined(__WHIRLPOOL__)|| defined(__ALL__)
  rc = sqlite3_create_function(db,"whirlpool", 1,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, whirlpool, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "whirlpoolblob", 4, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, whirlpoolblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__)
  rc = sqlite3_create_function(db, "macwhirlpool", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macwhirlpool, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  rc = sqlite3_create_function(db, "macwhirlpoolblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macwhirlpoolblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif

#if (defined(__CMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"maccmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maccmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "maccmacblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maccmacblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"maccbccmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, maccbccmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "maccbccmacblob", 6 SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, maccbccmacblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__DMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"macdmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macdmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "macdmacblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macdmacblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__GMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"macgmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macgmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "macgmacblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macgmacblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__HMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"machmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, machmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "machmacblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, machmacblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__POLY1305__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"macpoly1305", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macpoly1305, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "macpoly1305blob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macpoly1305blob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"mactwotrack", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, mactwotrack, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "mactwotrackblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, mactwotrackblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
#if (defined(__VMAC__)|| defined(__ALL__))&& defined(__USE_MAC__)
  rc = sqlite3_create_function(db,"macvmac", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, macvmac, 0, 0);
  if ( rc != SQLITE_OK) return rc;
#if defined(__BLOB__)
  rc = sqlite3_create_function(db, "macvmacblob", 6, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, macvmacblob, 0, 0);
  if (rc != SQLITE_OK) return rc;
#endif
#endif
  rc = sqlite3_create_function(db,"fromhex", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, fromhex, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db,"tohex", 3,SQLITE_UTF8|SQLITE_INNOCUOUS|SQLITE_DETERMINISTIC,0, tohex, 0, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_function(db, "tobase2", 3, SQLITE_UTF8 | SQLITE_INNOCUOUS | SQLITE_DETERMINISTIC, 0, tobase2, 0, 0);
  if (rc != SQLITE_OK) return rc;

  rc = sqlite3_create_module(db,"hash_info", &hash_info_Module, 0);
  if ( rc != SQLITE_OK) return rc;

  rc = sqlite3_create_module(db,"hash_sizes", &hash_sizes_Module, 0);
  if ( rc != SQLITE_OK) return rc;

  return rc;
}