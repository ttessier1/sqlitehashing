#pragma once 
//#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#ifndef SQLITE_OMIT_VIRTUALTABLE

#define HASH_INFO_MODULE_NAME "hashing"
#define HASH_INFO_FUNCTION_NAME_1 "hash_info"
#define HASH_INFO_COLUMN_TYPE_1 "table"
#define HASH_INFO_COLUMN_SIGNATURE_1 "select * FROM hash_info();"
#define HASH_INFO_FUNCTION_VERSION_1 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_1 "2024-19-01-01:01:01"
#define HASH_INFO_FUNCTION_NAME_2 "hash_size"
#define HASH_INFO_COLUMN_TYPE_2 "table"
#define HASH_INFO_COLUMN_SIGNATURE_2 "select * FROM hash_sizes();"
#define HASH_INFO_FUNCTION_VERSION_2 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_2 "2024-19-01-01:01:01"
#define HASH_INFO_FUNCTION_NAME_3 "hash_ping"
#define HASH_INFO_COLUMN_SIGNATURE_3 "select hash_ping();"
#define HASH_INFO_COLUMN_TYPE_3 "util"
#define HASH_INFO_FUNCTION_VERSION_3 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_3 "2024-19-01-01:01:01"
#define HASH_INFO_FUNCTION_NAME_4 "rot13"
#define HASH_INFO_COLUMN_TYPE_4 "transform"
#define HASH_INFO_COLUMN_SIGNATURE_4 "select rot('');"
#define HASH_INFO_FUNCTION_VERSION_4 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_4 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_5 "md2"
#define HASH_INFO_COLUMN_TYPE_5 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_5 "select md2('');"
#define HASH_INFO_FUNCTION_VERSION_5 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_5 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_6 "md4"
#define HASH_INFO_COLUMN_TYPE_6 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_6 "select md4('');"
#define HASH_INFO_FUNCTION_VERSION_6 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_6 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_7 "md5"
#define HASH_INFO_COLUMN_TYPE_7 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_7 "select md5('');"
#define HASH_INFO_FUNCTION_VERSION_7 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_7 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_8 "sha1"
#define HASH_INFO_COLUMN_TYPE_8 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_8 "select sha1('');"
#define HASH_INFO_FUNCTION_VERSION_8 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_8 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_9 "sha224"
#define HASH_INFO_COLUMN_TYPE_9 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_9 "select md2('');"
#define HASH_INFO_FUNCTION_VERSION_9 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_9 "2024-19-01-01:01:01"


#define HASH_INFO_FUNCTION_NAME_10 "sha256"
#define HASH_INFO_COLUMN_TYPE_10 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_10 "select sha256('');"
#define HASH_INFO_FUNCTION_VERSION_10 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_10 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_11 "sha384"
#define HASH_INFO_COLUMN_TYPE_11 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_11 "select sha384('');"
#define HASH_INFO_FUNCTION_VERSION_11 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_11 "2024-19-01-01:01:01"


#define HASH_INFO_FUNCTION_NAME_12 "sha512"
#define HASH_INFO_COLUMN_TYPE_12 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_12 "select sha512('');"
#define HASH_INFO_FUNCTION_VERSION_12 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_12 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_13 "sha3-224"
#define HASH_INFO_COLUMN_TYPE_13 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_13 "select sha3224('');"
#define HASH_INFO_FUNCTION_VERSION_13 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_13 "2024-19-01-01:01:01"


#define HASH_INFO_FUNCTION_NAME_14 "sha3-256"
#define HASH_INFO_COLUMN_TYPE_14 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_14 "select sha3256('');"
#define HASH_INFO_FUNCTION_VERSION_14 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_14 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_15 "sha3-384"
#define HASH_INFO_COLUMN_TYPE_15 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_15 "select sha3384('');"
#define HASH_INFO_FUNCTION_VERSION_15 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_15 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_16 "sha3-512"
#define HASH_INFO_COLUMN_TYPE_16 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_16 "select sha3512('');"
#define HASH_INFO_FUNCTION_VERSION_16 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_16 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_17 "ripemd-128"
#define HASH_INFO_COLUMN_TYPE_17 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_17 "select ripemd128('');"
#define HASH_INFO_FUNCTION_VERSION_17 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_17 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_18 "ripemd-160"
#define HASH_INFO_COLUMN_TYPE_18 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_18 "select ripemd160('');"
#define HASH_INFO_FUNCTION_VERSION_18 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_18 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_19 "ripemd-256"
#define HASH_INFO_COLUMN_TYPE_19 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_19 "select ripemd256('');"
#define HASH_INFO_FUNCTION_VERSION_19 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_19 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_20 "ripemd-320"
#define HASH_INFO_COLUMN_TYPE_20 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_20 "select ripemd320('');"
#define HASH_INFO_FUNCTION_VERSION_20 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_20 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_21 "blake2b"
#define HASH_INFO_COLUMN_TYPE_21 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_21 "select blake2b('');"
#define HASH_INFO_FUNCTION_VERSION_21 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_21 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_22 "blake2s"
#define HASH_INFO_COLUMN_TYPE_22 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_22 "select blake2s('');"
#define HASH_INFO_FUNCTION_VERSION_22 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_22 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_23 "tiger"
#define HASH_INFO_COLUMN_TYPE_23 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_23 "select tiger('');"
#define HASH_INFO_FUNCTION_VERSION_23 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_23 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_24 "shake128"
#define HASH_INFO_COLUMN_TYPE_24 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_24 "select shake128('');"
#define HASH_INFO_FUNCTION_VERSION_24 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_24 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_25 "shake256"
#define HASH_INFO_COLUMN_TYPE_25 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_25 "select shake256('');"
#define HASH_INFO_FUNCTION_VERSION_25 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_25 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_26 "siphash64"
#define HASH_INFO_COLUMN_TYPE_26 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_26 "select siphash64('');"
#define HASH_INFO_FUNCTION_VERSION_26 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_26 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_27 "siphash128"
#define HASH_INFO_COLUMN_TYPE_27 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_27 "select siphash128('');"
#define HASH_INFO_FUNCTION_VERSION_27 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_27 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_28 "lsh224"
#define HASH_INFO_COLUMN_TYPE_28 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_28 "select lsh224('');"
#define HASH_INFO_FUNCTION_VERSION_28 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_28 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_29 "lsh256"
#define HASH_INFO_COLUMN_TYPE_29 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_29 "select lsh256('');"
#define HASH_INFO_FUNCTION_VERSION_29 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_29 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_30 "lsh384"
#define HASH_INFO_COLUMN_TYPE_30 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_30 "select lsh384('');"
#define HASH_INFO_FUNCTION_VERSION_30 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_30 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_31 "lsh512"
#define HASH_INFO_COLUMN_TYPE_31 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_31 "select lsh512('');"
#define HASH_INFO_FUNCTION_VERSION_31 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_31 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_32 "sm3"
#define HASH_INFO_COLUMN_TYPE_32 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_32 "select sm3('');"
#define HASH_INFO_FUNCTION_VERSION_32 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_32 "2024-19-01-01:01:01"

#define HASH_INFO_FUNCTION_NAME_33 "whirlpool"
#define HASH_INFO_COLUMN_TYPE_33 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_33 "select whirlpool('');"
#define HASH_INFO_FUNCTION_VERSION_33 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_33 "2024-19-01-01:01:01"


#define HASH_INFO_MAX 34

typedef struct hash_info_Spec {
  sqlite3_int64 iBase;         /* Starting value ("start") */
  sqlite3_int64 iTerm;         /* Given terminal value ("stop") */
  sqlite3_int64 iStep;         /* Increment ("step") */
  sqlite3_uint64 uSeqIndexMax; /* maximum sequence index (aka "n") */
  sqlite3_uint64 uSeqIndexNow; /* Current index during generation */
  sqlite3_int64 iValueNow;     /* Current value during generation */
  uint8_t isNotEOF;                 /* Sequence generation not exhausted */
  uint8_t isReversing;              /* Sequence is being reverse generated */
} hash_info_Spec;

typedef struct hash_info_cursor hash_info_cursor;
struct hash_info_cursor {
  sqlite3_vtab_cursor base;  /* Base class - must be first */
  sqlite3_int64 iRowid;      /* The rowid */
  hash_info_Spec hiS;
};

/* Column numbers */
#define HASH_INFO_COLUMN_MODULE_NAME 0
#define HASH_INFO_COLUMN_FUNCTION_NAME 1
#define HASH_INFO_COLUMN_TYPE 2
#define HASH_INFO_COLUMN_SIGNATURE 3
#define HASH_INFO_COLUMN_VERSION  4
#define HASH_INFO_COLUMN_DATE_CREATED 5

#ifndef LARGEST_UINT64
#define LARGEST_UINT64 (0xffffffff|(((sqlite3_uint64)0xffffffff)<<32))
#endif

#ifndef SQLITE_SERIES_CONSTRAINT_VERIFY
# define SQLITE_SERIES_CONSTRAINT_VERIFY 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

static int hash_info_Connect(
  sqlite3 *db,
  void *pUnused,
  int argcUnused, const char *const*argvUnused,
  sqlite3_vtab **ppVtab,
  char **pzErrUnused
){
    sqlite3_vtab *pNew;
    int rc;
    (void)pUnused;
    (void)argcUnused;
    (void)argvUnused;
    (void)pzErrUnused;
    rc = sqlite3_declare_vtab(db,"CREATE TABLE x(module_name,function_name,version,datecreated)");
    if( rc==SQLITE_OK ){
        pNew = *ppVtab = sqlite3_malloc( sizeof(*pNew) );
        if( pNew==0 ) return SQLITE_NOMEM;
            memset(pNew, 0, sizeof(*pNew));
        sqlite3_vtab_config(db, SQLITE_VTAB_INNOCUOUS);
    }
    return rc;
}

/*
** This method is the destructor for hash_info_Disconnect objects.
*/
static int hash_info_Disconnect(sqlite3_vtab *pVtab){
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

/*
** Constructor for a new hash_info_Open object.
*/
static int hash_info_Open(sqlite3_vtab *pUnused, sqlite3_vtab_cursor **ppCursor){
    hash_info_cursor *pCur;
    (void)pUnused;
    pCur = sqlite3_malloc( sizeof(*pCur) );
    if( pCur==0 ) return SQLITE_NOMEM;
    memset(pCur, 0, sizeof(*pCur));
    *ppCursor = &pCur->base;
    return SQLITE_OK;
}

/*
** Destructor for a hash_info_Close.
*/
static int hash_info_Close(sqlite3_vtab_cursor *cur){
    sqlite3_free(cur);
    return SQLITE_OK;
}

/*
** Advance a series_cursor to its next row of output.
*/
static int hash_info_Next(sqlite3_vtab_cursor *cur){
    hash_info_cursor *pCur = (hash_info_cursor*)cur;
    pCur->iRowid++;
    return SQLITE_OK;
}

static int hash_info_Column(
  sqlite3_vtab_cursor *cur,   /* The cursor */
  sqlite3_context *ctx,       /* First argument to sqlite3_result_...() */
  int i                       /* Which column to return */
){
  hash_info_cursor *pCur = (hash_info_cursor*)cur;
  if( pCur->iRowid == 1 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_1), strlen(HASH_INFO_FUNCTION_NAME_1), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_1), strlen(HASH_INFO_COLUMN_TYPE_1), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_1), strlen(HASH_INFO_COLUMN_SIGNATURE_1), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_1), strlen(HASH_INFO_FUNCTION_VERSION_1), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_1), strlen(HASH_INFO_FUNCTION_DATE_1), free);
        break;
    }
  }
  else if( pCur->iRowid == 2 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_2), strlen(HASH_INFO_FUNCTION_NAME_2), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_2), strlen(HASH_INFO_COLUMN_TYPE_2), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_2), strlen(HASH_INFO_COLUMN_SIGNATURE_2), free);
        break;

        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_2), strlen(HASH_INFO_FUNCTION_VERSION_2), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_2), strlen(HASH_INFO_FUNCTION_DATE_2), free);
        break;
    }
  }
  else if( pCur->iRowid == 3 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_3), strlen(HASH_INFO_FUNCTION_NAME_3), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_3), strlen(HASH_INFO_COLUMN_TYPE_3), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_3), strlen(HASH_INFO_COLUMN_SIGNATURE_3), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_3), strlen(HASH_INFO_FUNCTION_VERSION_3), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_3), strlen(HASH_INFO_FUNCTION_DATE_3), free);
        break;
    }
  }
  else if( pCur->iRowid == 4 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_4), strlen(HASH_INFO_FUNCTION_NAME_4), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_4), strlen(HASH_INFO_COLUMN_TYPE_4), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_4), strlen(HASH_INFO_COLUMN_SIGNATURE_4), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_4), strlen(HASH_INFO_FUNCTION_VERSION_4), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_4), strlen(HASH_INFO_FUNCTION_DATE_4), free);
        break;
    }
  }
   else if( pCur->iRowid == 5 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_5), strlen(HASH_INFO_FUNCTION_NAME_5), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_5), strlen(HASH_INFO_COLUMN_TYPE_5), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_5), strlen(HASH_INFO_COLUMN_SIGNATURE_5), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_5), strlen(HASH_INFO_FUNCTION_VERSION_5), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_5), strlen(HASH_INFO_FUNCTION_DATE_5), free);
        break;
    }
  }
  else if( pCur->iRowid == 6 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_6), strlen(HASH_INFO_FUNCTION_NAME_6), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_6), strlen(HASH_INFO_COLUMN_TYPE_6), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_6), strlen(HASH_INFO_COLUMN_SIGNATURE_6), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_6), strlen(HASH_INFO_FUNCTION_VERSION_6), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_6), strlen(HASH_INFO_FUNCTION_DATE_6), free);
        break;
    }
  }
  else if( pCur->iRowid == 7 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_7), strlen(HASH_INFO_FUNCTION_NAME_7), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_7), strlen(HASH_INFO_COLUMN_TYPE_7), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_7), strlen(HASH_INFO_COLUMN_SIGNATURE_7), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_7), strlen(HASH_INFO_FUNCTION_VERSION_7), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_7), strlen(HASH_INFO_FUNCTION_DATE_7), free);
        break;
    }
  }
  else if( pCur->iRowid == 8 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_8), strlen(HASH_INFO_FUNCTION_NAME_8), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_8), strlen(HASH_INFO_COLUMN_TYPE_8), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_9), strlen(HASH_INFO_COLUMN_SIGNATURE_8), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_8), strlen(HASH_INFO_FUNCTION_VERSION_8), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_8), strlen(HASH_INFO_FUNCTION_DATE_8), free);
        break;
    }
  }
  else if( pCur->iRowid == 9 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_9), strlen(HASH_INFO_FUNCTION_NAME_9), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_9), strlen(HASH_INFO_COLUMN_TYPE_9), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_9), strlen(HASH_INFO_COLUMN_SIGNATURE_9), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_9), strlen(HASH_INFO_FUNCTION_VERSION_9), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_9), strlen(HASH_INFO_FUNCTION_DATE_9), free);
        break;
    }
  }
  else if( pCur->iRowid == 10 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_10), strlen(HASH_INFO_FUNCTION_NAME_10), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_10), strlen(HASH_INFO_COLUMN_TYPE_10), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_10), strlen(HASH_INFO_COLUMN_SIGNATURE_10), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_10), strlen(HASH_INFO_FUNCTION_VERSION_10), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_10), strlen(HASH_INFO_FUNCTION_DATE_10), free);
        break;
    }
  }
  else if( pCur->iRowid == 11 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_11), strlen(HASH_INFO_FUNCTION_NAME_11), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_11), strlen(HASH_INFO_COLUMN_TYPE_11), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_11), strlen(HASH_INFO_COLUMN_SIGNATURE_11), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_11), strlen(HASH_INFO_FUNCTION_VERSION_11), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_11), strlen(HASH_INFO_FUNCTION_DATE_11), free);
        break;
    }
  }
  else if( pCur->iRowid == 12 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_12), strlen(HASH_INFO_FUNCTION_NAME_12), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_12), strlen(HASH_INFO_COLUMN_TYPE_12), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_12), strlen(HASH_INFO_COLUMN_SIGNATURE_12), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_12), strlen(HASH_INFO_FUNCTION_VERSION_12), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_12), strlen(HASH_INFO_FUNCTION_DATE_12), free);
        break;
    }
  }
  else if( pCur->iRowid == 13 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_13), strlen(HASH_INFO_FUNCTION_NAME_13), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_13), strlen(HASH_INFO_COLUMN_TYPE_13), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_13), strlen(HASH_INFO_COLUMN_SIGNATURE_13), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_13), strlen(HASH_INFO_FUNCTION_VERSION_13), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_13), strlen(HASH_INFO_FUNCTION_DATE_13), free);
        break;
    }
  }
  else if( pCur->iRowid == 14 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_14), strlen(HASH_INFO_FUNCTION_NAME_14), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_14), strlen(HASH_INFO_COLUMN_TYPE_14), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_14), strlen(HASH_INFO_COLUMN_SIGNATURE_14), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_14), strlen(HASH_INFO_FUNCTION_VERSION_14), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_14), strlen(HASH_INFO_FUNCTION_DATE_14), free);
        break;
    }
  }
  else if( pCur->iRowid == 15 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_15), strlen(HASH_INFO_FUNCTION_NAME_15), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_15), strlen(HASH_INFO_COLUMN_TYPE_15), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_15), strlen(HASH_INFO_COLUMN_SIGNATURE_15), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_15), strlen(HASH_INFO_FUNCTION_VERSION_15), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_15), strlen(HASH_INFO_FUNCTION_DATE_15), free);
        break;
    }
  }
  else if( pCur->iRowid == 16 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_16), strlen(HASH_INFO_FUNCTION_NAME_16), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_16), strlen(HASH_INFO_COLUMN_TYPE_16), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_16), strlen(HASH_INFO_COLUMN_SIGNATURE_16), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_16), strlen(HASH_INFO_FUNCTION_VERSION_16), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_16), strlen(HASH_INFO_FUNCTION_DATE_16), free);
        break;
    }
  }
  else if( pCur->iRowid == 17 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_17), strlen(HASH_INFO_FUNCTION_NAME_17), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_17), strlen(HASH_INFO_COLUMN_TYPE_17), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_17), strlen(HASH_INFO_COLUMN_SIGNATURE_17), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_17), strlen(HASH_INFO_FUNCTION_VERSION_17), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_17), strlen(HASH_INFO_FUNCTION_DATE_17), free);
        break;
    }
  }
  else if( pCur->iRowid == 18 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_18), strlen(HASH_INFO_FUNCTION_NAME_18), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_18), strlen(HASH_INFO_COLUMN_TYPE_18), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_18), strlen(HASH_INFO_COLUMN_SIGNATURE_18), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_18), strlen(HASH_INFO_FUNCTION_VERSION_18), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_18), strlen(HASH_INFO_FUNCTION_DATE_18), free);
        break;
    }
  }
  else if( pCur->iRowid == 19 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_19), strlen(HASH_INFO_FUNCTION_NAME_19), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_19), strlen(HASH_INFO_COLUMN_TYPE_19), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_19), strlen(HASH_INFO_COLUMN_SIGNATURE_19), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_19), strlen(HASH_INFO_FUNCTION_VERSION_19), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_19), strlen(HASH_INFO_FUNCTION_DATE_19), free);
        break;
    }
  }
  else if( pCur->iRowid == 20 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_20), strlen(HASH_INFO_FUNCTION_NAME_20), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_20), strlen(HASH_INFO_COLUMN_TYPE_20), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_20), strlen(HASH_INFO_COLUMN_SIGNATURE_20), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_20), strlen(HASH_INFO_FUNCTION_VERSION_20), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_20), strlen(HASH_INFO_FUNCTION_DATE_20), free);
        break;
    }
  }
   else if( pCur->iRowid == 21 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_21), strlen(HASH_INFO_FUNCTION_NAME_21), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_21), strlen(HASH_INFO_COLUMN_TYPE_21), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_21), strlen(HASH_INFO_COLUMN_SIGNATURE_21), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_21), strlen(HASH_INFO_FUNCTION_VERSION_21), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_21), strlen(HASH_INFO_FUNCTION_DATE_21), free);
        break;
    }
  }
  else if( pCur->iRowid == 22 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_22), strlen(HASH_INFO_FUNCTION_NAME_22), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_22), strlen(HASH_INFO_COLUMN_TYPE_22), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_22), strlen(HASH_INFO_COLUMN_SIGNATURE_22), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_22), strlen(HASH_INFO_FUNCTION_VERSION_22), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_22), strlen(HASH_INFO_FUNCTION_DATE_22), free);
        break;
    }
  }
  else if( pCur->iRowid == 23 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_23), strlen(HASH_INFO_FUNCTION_NAME_23), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_23), strlen(HASH_INFO_COLUMN_TYPE_23), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_24), strlen(HASH_INFO_COLUMN_SIGNATURE_24), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_23), strlen(HASH_INFO_FUNCTION_VERSION_23), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_23), strlen(HASH_INFO_FUNCTION_DATE_23), free);
        break;
    }
  }
  else if( pCur->iRowid == 24 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_24), strlen(HASH_INFO_FUNCTION_NAME_24), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_24), strlen(HASH_INFO_COLUMN_TYPE_24), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_24), strlen(HASH_INFO_FUNCTION_VERSION_24), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_24), strlen(HASH_INFO_FUNCTION_DATE_24), free);
        break;
    }
  }
  else if( pCur->iRowid == 25 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_25), strlen(HASH_INFO_FUNCTION_NAME_25), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_25), strlen(HASH_INFO_COLUMN_TYPE_25), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_25), strlen(HASH_INFO_COLUMN_SIGNATURE_25), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_25), strlen(HASH_INFO_FUNCTION_VERSION_25), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_25), strlen(HASH_INFO_FUNCTION_DATE_25), free);
        break;
    }
  }
  else if( pCur->iRowid == 26 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_26), strlen(HASH_INFO_FUNCTION_NAME_26), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_26), strlen(HASH_INFO_COLUMN_TYPE_26), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_26), strlen(HASH_INFO_COLUMN_SIGNATURE_26), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_26), strlen(HASH_INFO_FUNCTION_VERSION_26), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_26), strlen(HASH_INFO_FUNCTION_DATE_26), free);
        break;
    }
  }
  else if( pCur->iRowid == 27 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_27), strlen(HASH_INFO_FUNCTION_NAME_27), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_27), strlen(HASH_INFO_COLUMN_TYPE_27), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_27), strlen(HASH_INFO_COLUMN_SIGNATURE_27), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_27), strlen(HASH_INFO_FUNCTION_VERSION_27), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_27), strlen(HASH_INFO_FUNCTION_DATE_27), free);
        break;
    }
  }
  else if( pCur->iRowid == 28 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_28), strlen(HASH_INFO_FUNCTION_NAME_28), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_28), strlen(HASH_INFO_COLUMN_TYPE_28), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_28), strlen(HASH_INFO_COLUMN_SIGNATURE_28), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_28), strlen(HASH_INFO_FUNCTION_VERSION_28), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_28), strlen(HASH_INFO_FUNCTION_DATE_28), free);
        break;
    }
  }
  else if( pCur->iRowid == 29 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_29), strlen(HASH_INFO_FUNCTION_NAME_29), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_29), strlen(HASH_INFO_COLUMN_TYPE_29), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_29), strlen(HASH_INFO_COLUMN_SIGNATURE_29), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_29), strlen(HASH_INFO_FUNCTION_VERSION_29), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_29), strlen(HASH_INFO_FUNCTION_DATE_29), free);
        break;
    }
  }
  else if( pCur->iRowid == 30 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_30), strlen(HASH_INFO_FUNCTION_NAME_30), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_30), strlen(HASH_INFO_COLUMN_TYPE_30), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_30), strlen(HASH_INFO_COLUMN_SIGNATURE_30), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_30), strlen(HASH_INFO_FUNCTION_VERSION_30), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_30), strlen(HASH_INFO_FUNCTION_DATE_30), free);
        break;
    }
  }
  else if( pCur->iRowid == 31 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_31), strlen(HASH_INFO_FUNCTION_NAME_31), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_31), strlen(HASH_INFO_COLUMN_TYPE_31), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_31), strlen(HASH_INFO_COLUMN_SIGNATURE_31), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_31), strlen(HASH_INFO_FUNCTION_VERSION_31), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_31), strlen(HASH_INFO_FUNCTION_DATE_31), free);
        break;
    }
  }
  else if( pCur->iRowid == 32 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_32), strlen(HASH_INFO_FUNCTION_NAME_32), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_32), strlen(HASH_INFO_COLUMN_TYPE_32), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_32), strlen(HASH_INFO_COLUMN_SIGNATURE_32), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_32), strlen(HASH_INFO_FUNCTION_VERSION_32), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_32), strlen(HASH_INFO_FUNCTION_DATE_32), free);
        break;
    }
  }
  else if( pCur->iRowid == 33 )
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_MODULE_NAME), strlen(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_NAME_33), strlen(HASH_INFO_FUNCTION_NAME_33), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_TYPE_33), strlen(HASH_INFO_COLUMN_TYPE_33), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strdup(HASH_INFO_COLUMN_SIGNATURE_33), strlen(HASH_INFO_COLUMN_SIGNATURE_33), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_VERSION_33), strlen(HASH_INFO_FUNCTION_VERSION_33), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strdup(HASH_INFO_FUNCTION_DATE_33), strlen(HASH_INFO_FUNCTION_DATE_33), free);
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

/*
** Return the rowid for the current row, logically equivalent to n+1 where
** "n" is the ascending integer in the aforesaid production definition.
*/
static int hash_info_Rowid(sqlite3_vtab_cursor *cur, sqlite_int64 *pRowid){
  hash_info_cursor *pCur = (hash_info_cursor*)cur;
  *pRowid = pCur->iRowid;
  return SQLITE_OK;
}

/*
** Return TRUE if the cursor has been moved off of the last
** row of output.
*/
static int hash_info_Eof (
    sqlite3_vtab_cursor *cur )
{
    hash_info_cursor *pCur = (hash_info_cursor*)cur;
    return (pCur->iRowid>=HASH_INFO_MAX);
}

static int hash_info_Filter (
    sqlite3_vtab_cursor *pVtabCursor,
    int idxNum, 
    const char *idxStrUnused,
    int argc, sqlite3_value **argv )
{
    hash_info_cursor *pCur = (hash_info_cursor*)pVtabCursor;
    pCur->iRowid = 1;
    return SQLITE_OK;
}

static int hash_info_BestIndex (
    sqlite3_vtab *tab,
    sqlite3_index_info *pIdxInfo )
{
    pIdxInfo->estimatedCost = (double)10;
    pIdxInfo->estimatedRows = 10;
    return SQLITE_OK;
}

#ifdef __cplusplus
}
#endif

static sqlite3_module hash_info_Module = {
  0,                         /* iVersion */
  0,                         /* xCreate */
  hash_info_Connect,             /* xConnect implemented */
  hash_info_BestIndex,           /* xBestIndex NOT implemented */
  hash_info_Disconnect,          /* xDisconnect implemented */
  0,                         /* xDestroy */
  hash_info_Open,                /* xOpen - open a cursor implemented */
  hash_info_Close,               /* xClose - close a cursor implemented */
  hash_info_Filter,              /* xFilter - configure scan constraints NOT implemented */
  hash_info_Next,                /* xNext - advance a cursor implemented */
  hash_info_Eof,                 /* xEof - check for end of scan */
  hash_info_Column,              /* xColumn - read data */
  hash_info_Rowid,               /* xRowid - read data */
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
