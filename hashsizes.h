#pragma once 
//#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#ifndef SQLITE_OMIT_VIRTUALTABLE

typedef struct hash_sizes_cursor hash_sizes_cursor;
struct hash_sizes_cursor {
  sqlite3_vtab_cursor base;  /* Base class - must be first */
  sqlite3_int64 iRowid;      /* The rowid */
};

/* Column numbers */
#define HASH_SIZE_COLUMN_MODULE_NAME 0
#define HASH_SIZE_COLUMN_FUNCTION_NAME 1
#define HASH_SIZE_COLUMN_HASH_SIZE 2

#define HASH_SIZE_MODULE_NAME "hashing"

#define HASH_SIZE_FUNCTION_NAME_1 "md2"
#define HASH_SIZE_FUNCTION_NAME_2 "md4"
#define HASH_SIZE_FUNCTION_NAME_3 "md5"
#define HASH_SIZE_FUNCTION_NAME_4 "sha1"
#define HASH_SIZE_FUNCTION_NAME_5 "sha224"
#define HASH_SIZE_FUNCTION_NAME_6 "sha256"
#define HASH_SIZE_FUNCTION_NAME_7 "sha384"
#define HASH_SIZE_FUNCTION_NAME_8 "sha512"
#define HASH_SIZE_FUNCTION_NAME_9 "sha3-224"
#define HASH_SIZE_FUNCTION_NAME_10 "sha3-256"
#define HASH_SIZE_FUNCTION_NAME_11 "sha3-384"
#define HASH_SIZE_FUNCTION_NAME_12 "sha3-512"

#define HASH_SIZE_FUNCTION_NAME_13 "ripemd-128"
#define HASH_SIZE_FUNCTION_NAME_14 "ripenmd-160"
#define HASH_SIZE_FUNCTION_NAME_15 "ripemd-256"
#define HASH_SIZE_FUNCTION_NAME_16 "ripemd-320"

#define HASH_SIZE_FUNCTION_NAME_17 "blake2b"
#define HASH_SIZE_FUNCTION_NAME_18 "blake2s"

#define HASH_SIZE_FUNCTION_NAME_19 "tiger"

#define HASH_SIZE_FUNCTION_NAME_20 "shake-128"
#define HASH_SIZE_FUNCTION_NAME_21 "shake-256"

#define HASH_SIZE_FUNCTION_NAME_22 "sip-hash64"
#define HASH_SIZE_FUNCTION_NAME_23 "sip-hash128"

#define HASH_SIZE_FUNCTION_NAME_24 "lsh-224"
#define HASH_SIZE_FUNCTION_NAME_25 "lsh-256"
#define HASH_SIZE_FUNCTION_NAME_26 "lsh-384"
#define HASH_SIZE_FUNCTION_NAME_27 "lsh-512"

#define HASH_SIZE_FUNCTION_NAME_28 "sm3"
#define HASH_SIZE_FUNCTION_NAME_29 "whirlpool"

#define HASH_SIZE_FUNCTION_NAME_30 "panama"
#define HASH_SIZE_FUNCTION_NAME_31 "des"
#define HASH_SIZE_FUNCTION_NAME_32 "arc4"
#define HASH_SIZE_FUNCTION_NAME_33 "seal"

#define HASH_SIZE_MAX 34

#ifndef LARGEST_UINT64
#define LARGEST_UINT64 (0xffffffff|(((sqlite3_uint64)0xffffffff)<<32))
#endif

#ifdef __cplusplus
extern "C" {
#endif

static int hash_sizes_Connect ( sqlite3 *db, void *pUnused, int argcUnused, const char *const*argvUnused, sqlite3_vtab **ppVtab, char **pzErrUnused )
{
  sqlite3_vtab *pNew;
  int rc;
  (void)pUnused;
  (void)argcUnused;
  (void)argvUnused;
  (void)pzErrUnused;

  rc = sqlite3_declare_vtab(db,"CREATE TABLE x(module_name,function_name,version,datecreated)");
  if( rc==SQLITE_OK ){
    pNew = *ppVtab = (sqlite3_vtab*)sqlite3_malloc( sizeof(*pNew) );
    if( pNew==0 )
    {
      return SQLITE_NOMEM;
    }
    memset(pNew, 0, sizeof(*pNew));
    sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
  }
  return rc;
}

static int hash_sizes_Disconnect ( sqlite3_vtab *pVtab )
{
  sqlite3_free(pVtab);
  return SQLITE_OK;
}

static int hash_sizes_Open ( sqlite3_vtab *pUnused, sqlite3_vtab_cursor **ppCursor )
{
  hash_sizes_cursor *pCur;
  (void)pUnused;
  pCur = (hash_sizes_cursor*)sqlite3_malloc( sizeof(*pCur) );
  if( pCur==0 ) return SQLITE_NOMEM;
  memset(pCur, 0, sizeof(*pCur));
  *ppCursor = &pCur->base;
  return SQLITE_OK;
}

static int hash_sizes_Close ( sqlite3_vtab_cursor *cur )
{
  sqlite3_free(cur);
  return SQLITE_OK;
}

static int hash_sizes_Next ( sqlite3_vtab_cursor *cur )
{
    hash_sizes_cursor *pCur = (hash_sizes_cursor*)cur;
    pCur->iRowid++;
    return SQLITE_OK;
}

static int hash_sizes_Column ( sqlite3_vtab_cursor *cur, sqlite3_context *ctx, int i )
{
    hash_sizes_cursor *pCur = (hash_sizes_cursor*)cur;
    if( pCur->iRowid == 1 )
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_1), strlen(HASH_SIZE_FUNCTION_NAME_1), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_md2));
            break;
        }
    }
    else if ( pCur->iRowid == 2 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_2), strlen(HASH_SIZE_FUNCTION_NAME_2), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_md4));
            break;
        }
    }
    else if ( pCur->iRowid == 3 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_3), strlen(HASH_SIZE_FUNCTION_NAME_3), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_md5));
            break;
        }
    }
    else if ( pCur->iRowid == 4 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_4), strlen(HASH_SIZE_FUNCTION_NAME_4), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha1));
            break;
        }
    }
    else if ( pCur->iRowid == 5 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_5), strlen(HASH_SIZE_FUNCTION_NAME_5), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha224));
            break;
        }
    }
    else if ( pCur->iRowid == 6 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_6), strlen(HASH_SIZE_FUNCTION_NAME_6), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha256));
            break;
        }
    }
    else if ( pCur->iRowid == 7 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_7), strlen(HASH_SIZE_FUNCTION_NAME_7), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha384));
            break;
        }
    }
    else if ( pCur->iRowid == 8 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_8), strlen(HASH_SIZE_FUNCTION_NAME_8), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha512));
            break;
        }
    }
    else if ( pCur->iRowid == 9 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_9), strlen(HASH_SIZE_FUNCTION_NAME_9), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha3_224));
            break;
        }
    }
    else if ( pCur->iRowid == 10 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_10), strlen(HASH_SIZE_FUNCTION_NAME_10), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha3_256));
            break;
        }
    }
    else if ( pCur->iRowid == 11 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_11), strlen(HASH_SIZE_FUNCTION_NAME_11), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha3_384));
            break;
        }
    }
    else if ( pCur->iRowid == 12 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_12), strlen(HASH_SIZE_FUNCTION_NAME_12), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sha3_512));
            break;
        }
    }
    else if ( pCur->iRowid == 13 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_13), strlen(HASH_SIZE_FUNCTION_NAME_13), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_ripemd_128));
            break;
        }
    }
     else if ( pCur->iRowid == 14 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_14), strlen(HASH_SIZE_FUNCTION_NAME_14), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_ripemd_160));
            break;
        }
    }
     else if ( pCur->iRowid == 15 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_15), strlen(HASH_SIZE_FUNCTION_NAME_15), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_ripemd_256));
            break;
        }
    }
    else if ( pCur->iRowid == 16 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_16), strlen(HASH_SIZE_FUNCTION_NAME_16), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_ripemd_320));
            break;
        }
    }
    else if ( pCur->iRowid == 17 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_17), strlen(HASH_SIZE_FUNCTION_NAME_17), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_blake2b));
            break;
        }
    }
    else if ( pCur->iRowid == 18 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_18), strlen(HASH_SIZE_FUNCTION_NAME_18), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_blake2s));
            break;
        }
    }
    else if ( pCur->iRowid == 19 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_19), strlen(HASH_SIZE_FUNCTION_NAME_19), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_tiger));
            break;
        }
    }
    else if ( pCur->iRowid == 20 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_20), strlen(HASH_SIZE_FUNCTION_NAME_20), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_shake_128));
            break;
        }
    }
    else if ( pCur->iRowid == 21 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_21), strlen(HASH_SIZE_FUNCTION_NAME_21), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_shake_256));
            break;
        }
    }
    else if ( pCur->iRowid == 22 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_22), strlen(HASH_SIZE_FUNCTION_NAME_22), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sip_hash64));
            break;
        }
    }
    else if ( pCur->iRowid == 23 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_23), strlen(HASH_SIZE_FUNCTION_NAME_23), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sip_hash128));
            break;
        }
    }
    else if ( pCur->iRowid == 24 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_24), strlen(HASH_SIZE_FUNCTION_NAME_24), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_lsh_224));
            break;
        }
    }
    else if ( pCur->iRowid == 25 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_25), strlen(HASH_SIZE_FUNCTION_NAME_25), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_lsh_256));
            break;
        }
    }
    else if ( pCur->iRowid == 26 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_26), strlen(HASH_SIZE_FUNCTION_NAME_26), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_lsh_384));
            break;
        }
    }
    else if ( pCur->iRowid == 27 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_27), strlen(HASH_SIZE_FUNCTION_NAME_27), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_lsh_512));
            break;
        }
    }
    else if ( pCur->iRowid == 28 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_28), strlen(HASH_SIZE_FUNCTION_NAME_28), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_sm3));
            break;
        }
    }
    else if ( pCur->iRowid == 29 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_29), strlen(HASH_SIZE_FUNCTION_NAME_29), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_whirlpool));
            break;
        }
    }
    else if ( pCur->iRowid == 30 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_30), strlen(HASH_SIZE_FUNCTION_NAME_30), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,0);
            break;
        }
    }
    else if ( pCur->iRowid == 31 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_31), strlen(HASH_SIZE_FUNCTION_NAME_31), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,0);
            break;
        }
    }
    else if ( pCur->iRowid == 32 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_32), strlen(HASH_SIZE_FUNCTION_NAME_32), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,0);
            break;
        }
    }
    else if ( pCur->iRowid == 33 ) 
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_MODULE_NAME), strlen(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strdup(HASH_SIZE_FUNCTION_NAME_33), strlen(HASH_SIZE_FUNCTION_NAME_33), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,0);
            break;
        }
    }
    else
    {
        sqlite3_result_error(ctx,"Invalid Cursor Position", strlen("Invalid Cursor Position"));
        return -1;
    }
    return SQLITE_OK;
}

static int hash_sizes_Rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid)
{
    hash_sizes_cursor *pCur = (hash_sizes_cursor*)cur;
    *pRowid = pCur->iRowid;
    return SQLITE_OK;
}

static int hash_sizes_Eof(sqlite3_vtab_cursor *cur)
{
    hash_sizes_cursor *pCur = (hash_sizes_cursor*)cur;
    return (pCur->iRowid>=HASH_SIZE_MAX);
}

static int hash_sizes_Filter ( sqlite3_vtab_cursor *pVtabCursor, int idxNum, const char *idxStrUnused, int argc, sqlite3_value **argv )
{
    hash_sizes_cursor *pCur = (hash_sizes_cursor*)pVtabCursor;
    pCur->iRowid = 1;
    return SQLITE_OK;
}

static int hash_sizes_BestIndex ( sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo )
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

#ifdef __cplusplus
} 
#endif

static sqlite3_module hash_sizes_Module = {
  0,                         /* iVersion */
  0,                         /* xCreate */
  hash_sizes_Connect,             /* xConnect implemented */
  hash_sizes_BestIndex,           /* xBestIndex NOT implemented */
  hash_sizes_Disconnect,          /* xDisconnect implemented */
  0,                         /* xDestroy */
  hash_sizes_Open,                /* xOpen - open a cursor implemented */
  hash_sizes_Close,               /* xClose - close a cursor implemented */
  hash_sizes_Filter,              /* xFilter - configure scan constraints NOT implemented */
  hash_sizes_Next,                /* xNext - advance a cursor implemented */
  hash_sizes_Eof,                 /* xEof - check for end of scan */
  hash_sizes_Column,              /* xColumn - read data */
  hash_sizes_Rowid,               /* xRowid - read data */
  0,                         /* xUpdate */
  0,                         /* xBegin */
  0,                         /* xSync */
  0,                         /* xCommit */
  0,                         /* xRollback */
  0,                         /* xFindMethod */
  0,                         /* xRename */
  0,                         /* xSavepoint */
  0,                         /* xRelease */
  0,                         /* xRollbackTo */
  0,                         /* xShadowName */
  0                          /* xIntegrity */
};

#endif /* SQLITE_OMIT_VIRTUALTABLE */
