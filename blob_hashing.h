#pragma once

#include <sqlite3ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_hashing.h"
#include "util.h"

//#define MIN(a,b) a<b?a:b
//#define MAX(a,b) a>b?a:b
int pagesize_callback(void* callbackVerify, int numberOfColumns, char** values, char** column_names);
int get_schema_page_size(sqlite3_context* context, sqlite3* db, const char* schema, int length);

int pagesize_callback(void* callbackVerify, int numberOfColumns, char** values, char** column_names)
{
    if (callbackVerify != NULL)
    {
        if (numberOfColumns == 1)
        {
            (*(int*)callbackVerify) = atoi(values[0]);
        }
    }
    return SQLITE_OK;
}

int get_schema_page_size(sqlite3_context* context, sqlite3* db, const char* schema, int length)
{
    int bufferLength = 0;
    char* buffer = NULL;
    char* errmsg;
    int pagesize;
    if (db != NULL && schema != NULL)
    {
        bufferLength = length + strlength("PRAGMA %s.page_size") + 1 - 2; // subtract %s from string but add null character length
        buffer = (char*)malloc(bufferLength);
        if (buffer)
        {

            sqlite3_snprintf(bufferLength, buffer, "PRAGMA %s.page_size", schema);
            if (sqlite3_exec(
                db,
                buffer,                           /* SQL to be evaluated */
                (void*)pagesize_callback,  /* Callback function */
                (void*)&pagesize,                                    /* 1st argument to callback */
                &errmsg                              /* Error msg written here */
            ) == SQLITE_OK)
            {
                free(buffer);
                return pagesize;
            }
            free(buffer);
            return -1;
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


//#if defined(__MD2__)|| defined(__ALL__)

static int blobmd2(
    sqlite3_context* context,
    int argc,
    sqlite3_value** argv
)
{
    DebugMessage("Blob Md2 Called\r\n");
    sqlite3* db=NULL;
    unsigned char* zOut;
    unsigned char* zToFree;
    int rc = 0;
    int nIn = 0;
    int index = 0;
    int nBlobTextSize = 0;
    unsigned int remainingSize = 0;
    unsigned int length=0;
    int offset = 0;
    const char* result;
    unsigned int buffer_size = 0;
    const char* database;
    const char* table;
    const char* column;
    char* buffer = NULL;
    sqlite_int64 rowid = 0;
    sqlite3_blob* blob;
    Md2ContextPtr contextPtr = NULL;
    if (context == NULL)
    {
        printf("Invalid Sqlite Context\r\n");
        return -1;
    }
    if (argc != 4)
    {
        sqlite3_result_error(context, "Invalid number of arguments", -1);
        return -1;
    }
    db = sqlite3_context_db_handle(context);
    if (db != NULL)
    {
        if (sqlite3_value_type(argv[0]) == SQLITE_NULL || sqlite3_value_type(argv[1]) == SQLITE_NULL || sqlite3_value_type(argv[2]) == SQLITE_NULL || sqlite3_value_type(argv[3]) == SQLITE_NULL)
        {
            sqlite3_result_error(context, "NULL values not allowed in blob functions", -1);
            return -1;
        }
        else if (
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
                    contextPtr = Md2Initialize();
                    while (rc == SQLITE_OK && remainingSize > 0)
                    {
                        length = MIN(buffer_size, remainingSize);
                        rc = sqlite3_blob_read(blob, buffer, length, offset);
                        if (rc == SQLITE_OK)
                        {
                            Md2Update(contextPtr, buffer,length);
                        }
                        remainingSize -= length;
                    }
                    result = Md2Finalize(contextPtr);
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
            }
        }
    }
    return SQLITE_OK;
}

//#endif
