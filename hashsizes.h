#pragma once 
//#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#ifndef SQLITE_OMIT_VIRTUALTABLE

typedef struct hash_sizes_cursor hash_sizes_cursor;
struct hash_sizes_cursor {
  sqlite3_vtab_cursor base;  /* Base class - must be first */
  sqlite3_int64 iRowid;      /* The rowid */
};

enum hash_sizes
{
    hash_size_first_record = 0, // allways 0 - next item will be 1 whatever it is
#if defined(__MD2__) || defined (__ALL__)
    hash_size_md2, // md2 enabled
#if defined(__USE_BLOB__)
    hash_size_md2blob, // md2 enabled
#endif
#if defined(__USE_MAC__)
    hash_size_md2mac, // md2 enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_md2macblob, // md2 enabled
#endif

#endif

#if defined(__MD4__) || defined (__ALL__)
    hash_size_md4, // md4 enabled
#if defined(__USE_BLOB__)
    hash_size_md4blob, // md4 enabled
#endif
#if defined(__USE_MAC__)
    hash_size_md4mac, // md4 enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_md4macblob, // md4 enabled
#endif
#endif

#if defined(__MD5__) || defined (__ALL__)
    hash_size_md5, // md5 enabled
#if defined(__USE_BLOB__)
    hash_size_md5blob, // md5 enabled
#endif
#if defined(__USE_MAC__)
    hash_size_md5mac, // md5 mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_md5macblob, // md5 mac enabled
#endif

#endif

#if defined(__SHA1__) || defined (__ALL__)
    hash_size_sha1, // sha1 enabled
#if defined(__USE_BLOB__)
    hash_size_sha1blob, // mdsha1blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha1mac, // mdsha1mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_sha1macblob, // mdsha1mac enabled
#endif
#endif

#if defined(__SHA224__) || defined (__ALL__)
    hash_size_sha224, // sha224 enabled
#if defined(__USE_BLOB__)
    hash_size_sha224blob, // mdsha224blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha224mac, // mdsha224mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_sha224macblob, // mdsha224mac enabled
#endif
#endif
#if defined(__SHA256__) || defined (__ALL__)
    hash_size_sha256, // sha256 enabled
#if defined(__USE_BLOB__)
    hash_size_sha256blob, // mdsha256blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha256mac, // mdsha256blob enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_sha256macblob, // mdsha256blob enabled
#endif
#endif

#if defined(__SHA384__) || defined (__ALL__)
    hash_size_sha384, // sha384 enabled
#if defined(__USE_BLOB__)
    hash_size_sha384blob, // mdsha384blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha384mac, // mdsha384blob enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_sha384macblob, // mdsha384blob enabled
#endif
#endif

#if defined(__SHA512__) || defined (__ALL__)
    hash_size_sha512, // sha512 enabled
#if defined(__USE_BLOB__)
    hash_size_sha512blob, // mdsha512blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha512mac, // mdsha512mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_sha512macblob, // mdsha512mac enabled
#endif
#endif

#if defined(__SHA3224__) || defined (__ALL__)
    hash_size_sha3224, // sha3224 enabled
#if defined(__USE_BLOB__)
    hash_size_sha3224blob, // mdsha3224blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha3224mac, // mdsha3224mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
hash_size_sha3224macblob, // mdsha3224mac enabled
#endif
#endif

#if defined(__SHA3256__) || defined (__ALL__)
    hash_size_sha3256, // sha3256 enabled
#if defined(__USE_BLOB__)
    hash_size_sha3256blob, // mdsha3256blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha3256mac, // mdsha3256mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_sha3256macblob, // mdsha3256mac enabled
#endif
#endif

#if defined(__SHA3384__) || defined (__ALL__)
    hash_size_sha3384, // sha3384 enabled
#if defined(__USE_BLOB__)
    hash_size_sha3384blob, // mdsha384blob enabled
#endif
#if defined(__USE_MAC__)
    hash_size_sha3384mac, // mdsha384mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_sha3384macblob, // mdsha384mac enabled
#endif
#endif

#if defined(__SHA3512__) || defined (__ALL__)
    hash_size_sha3512, // sha3512 enabled
#if defined(__USE_BLOB__)
        hash_size_sha3512blob, // mdsha3512blob enabled
#endif
#if defined(__USE_MAC__)
        hash_size_sha3512mac, // mdsha3512mac enabled
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_sha3512macblob, // mdsha3512mac enabled
#endif
#endif

#if defined(__RIPEMD128__) || defined (__ALL__)
    hash_size_ripemd128,
#if defined(__USE_BLOB__)
        hash_size_ripemd128blob,
#endif
#if defined(__USE_MAC__)
        hash_size_ripemd128mac,
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_ripemd128macblob,
#endif
#endif
#if defined(__RIPEMD160__) || defined (__ALL__)
    hash_size_ripemd160,
#if defined(__USE_BLOB__)
        hash_size_ripemd160blob,
#endif
#if defined(__USE_MAC__)
        hash_size_ripemd160mac,
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_ripemd160macblob,
#endif
#endif

#if defined(__RIPEMD256__) || defined (__ALL__)
    hash_size_ripemd256,
#if defined(__USE_BLOB__)
        hash_size_ripemd256blob,
#endif
#if defined(__USE_MAC__)
        hash_size_ripemd256mac,
#endif
#if defined(__USE_MAC__) &&  defined(__USE_BLOB__)
        hash_size_ripemd256macblob,
#endif
#endif

#if defined(__RIPEMD320__) || defined (__ALL__)
    hash_size_ripemd320,
#if defined(__USE_BLOB__)
    hash_size_ripemd320blob,
#endif
#if defined(__USE_MAC__)
    hash_size_ripemd320mac,
#endif
#if defined(__USE_MAC__)
    hash_size_ripemd320macblob,
#endif
#endif

#if defined(__BLAKE2B__) || defined (__ALL__)
    hash_size_blake2b,
#if defined(__USE_BLOB__)
        hash_size_blake2bblob,
#endif
#if defined(__USE_MAC__)
        hash_size_blake2bmac,
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_blake2bmacblob,
#endif
#endif

#if defined(__BLAKE2S__) || defined (__ALL__)
    hash_size_blake2s,
#if defined(__USE_BLOB__)
    hash_size_blake2sblob,
#endif
#if defined(__USE_MAC__)
    hash_size_blake2smac,
#endif
#if defined(__USE_MAC__) &&  defined(__USE_BLOB__)
    hash_size_blake2smacblob,
#endif
#endif

#if defined(__TIGER__) || defined (__ALL__)
    hash_size_tiger,
#if defined(__USE_BLOB__)
    hash_size_tigerblob,
#endif
#if defined(__USE_MAC__)
    hash_size_tigermac,
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_size_tigermacblob,
#endif
#endif

#if defined(__SHAKE128__) || defined (__ALL__)
    hash_size_shake128,
#if defined(__USE_BLOB__)
    hash_size_shake128blob,
#endif
#if defined(__USE_MAC__)
        hash_size_shake128mac,
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_shake128macblob,
#endif
#endif

#if defined(__SHAKE256__) || defined (__ALL__)
    hash_size_shake256,
#if defined(__USE_BLOB__)
    hash_size_shake256blob,
#endif
#if defined(__USE_MAC__)
        hash_size_shake256mac,
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_size_shake256macblob,
#endif
#endif

#if defined(__SIPHASH64__) || defined (__ALL__)
    hash_size_siphash64,
#if defined(__USE_BLOB__)
    hash_size_siphash64blob,
#endif
#if defined(__USE_MAC__)
            hash_size_siphash64mac,
#endif
#endif

#if defined(__SIPHASH128__) || defined (__ALL__)
    hash_size_siphash128,
#if defined(__USE_BLOB__)
    hash_size_siphash128blob,
#endif
#if defined(__USE_MAC__)
    hash_size_siphash128mac,
#endif
#endif

#if defined(__LSH224__) || defined (__ALL__)
    hash_size_lsh224,
#if defined(__USE_BLOB__)
    hash_size_lsh224blob,
#endif
#if defined(__USE_MAC__)
    hash_size_lsh224mac,
#endif
#endif

#if defined(__LSH256__) || defined (__ALL__)
    hash_size_lsh256,
#if defined(__USE_BLOB__)
    hash_size_lsh256blob,
#endif
#if defined(__USE_MAC__)
    hash_size_lsh256mac,
#endif
#endif

#if defined(__LSH384__) || defined (__ALL__)
    hash_size_lsh384,
#if defined(__USE_BLOB__)
    hash_size_lsh384blob,
#endif
#if defined(__USE_MAC__)
    hash_size_lsh384mac,
#endif
#endif

#if defined(__LSH512__) || defined (__ALL__)
    hash_size_lsh512,
#if defined(__USE_BLOB__)
    hash_size_lsh512blob,
#endif
#if defined(__USE_MAC__)
    hash_size_lsh512mac,
#endif
#endif

#if defined(__SM3__) || defined (__ALL__)
    hash_size_sm3,
#if defined(__USE_BLOB__)
    hash_size_sm3blob,
#endif
#if defined(__USE_MAC__)
    hash_size_sm3mac,
#endif
#endif

#if defined(__WHIRLPOOL__) || defined (__ALL__)
    hash_size_whirlpool,
#if defined(__USE_BLOB__)
    hash_size_whirlpoolblob,
#endif
#if defined(__USE_MAC__)
    hash_size_whirlpoolmac,
#endif
#endif
#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_cmac,
#endif
#if (defined(__CBCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_cbcmac,
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_dmac,
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_gmac,
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_hmac,
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
    hash_size_poly1305mac,
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_twotrackmac,
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
         hash_size_vmacmac,
#endif

    hash_size_hash_max
};

/* Column numbers */
#define HASH_SIZE_COLUMN_MODULE_NAME 0
#define HASH_SIZE_COLUMN_FUNCTION_NAME 1
#define HASH_SIZE_COLUMN_HASH_SIZE 2

#define HASH_SIZE_MODULE_NAME "hashing"

#if defined(__MD2__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_MD2 "md2"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_MD2BLOB "md2blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_MD2MAC "macmd2"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_MD2MACBLOB "macmd2blob"
#endif
#endif

#if defined(__MD4__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_MD4 "md4"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_MD4BLOB "md4blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_MD4MAC "macmd4"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_MD4MACBLOB "macmd4blob"
#endif
#endif

#if defined(__MD5__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_MD5 "md5"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_MD5BLOB "md5blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_MD5MAC "macmd5"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_MD5MACBLOB "macmd5blob"
#endif
#endif

#if defined(__SHA1__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA1 "sha1"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA1BLOB "sha1blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA1MAC "macsha1"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA1MACBLOB "macsha1blob"
#endif
#endif


#if defined(__SHA224__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA224 "sha224"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA224BLOB "sha224blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA224MAC "macsha224"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA224MACBLOB "macsha224blob"
#endif
#endif



#if defined(__SHA256__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA256 "sha256"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA256BLOB "sha256blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA256MAC "macsha256"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA256MACBLOB "macsha256blob"
#endif
#endif

#if defined(__SHA384__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA384 "sha384"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA384BLOB "sha384blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA384MAC "macsha384"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA384MACBLOB "macsha384blob"
#endif
#endif

#if defined(__SHA512__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA512 "sha512"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA512BLOB "sha512blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA512MAC "macsha512"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA512MACBLOB "macsha512blob"
#endif
#endif



#if defined(__SHA3224__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA3224 "sha3224"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3224BLOB "sha3224blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA3224MAC "macsha3224"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3224MACBLOB "macsha3224blob"
#endif
#endif


#if defined(__SHA3256__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA3256 "sha3256"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3256BLOB "sha3256blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA3256MAC "macsha3256"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3256MACBLOB "macsha3256blob"
#endif
#endif



#if defined(__SHA3384__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA3384 "sha3384"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3384BLOB "sha3384blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA3384MAC "macsha3384"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3384MACBLOB "macsha3384blob"
#endif
#endif



#if defined(__SHA3512__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHA3512 "sha3512"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3512BLOB "sha3512blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHA3512MAC "macsha3512"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHA3512MACBLOB "macsha3512blob"
#endif
#endif

#if defined(__RIPEMD128__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD128 "ripemd128"

#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD128BLOB "ripemd128blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD128MAC "macripemd128"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD128MACBLOB "macripemd128blob"
#endif
#endif

#if defined(__RIPEMD160__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD160 "ripenmd160"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD160BLOB "ripenmd160blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD160MAC "macripenmd160"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD160MACBLOB "macripenmd160blob"
#endif
#endif



#if defined(__RIPEMD256__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD256 "ripemd256"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD256BLOB "ripemd256blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD256MAC "macripemd256"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD256MACBLOB "macripemd256blob"
#endif
#endif



#if defined(__RIPEMD320__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD320 "ripemd320"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD320BLOB "ripemd320blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD320MAC "macripemd320"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_RIPEMD320MACBLOB "macripemd320blob"
#endif
#endif

#if defined(__BLAKE2B__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2B "blake2b" 
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2BBLOB "blake2bblob" 
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2BMAC "macblake2b" 
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2BMACBLOB "macblake2bblob" 
#endif
#endif


#if defined(__BLAKE2S__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2S "blake2s"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2SBLOB "blake2sblob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2SMAC "macblake2s"
#endif
#if defined(__USE_MAC__) &&  defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_BLAKE2SMACBLOB "macblake2sblob"
#endif
#endif

#if defined(__TIGER__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_TIGER "tiger"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_TIGERBLOB "tigerblob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_TIGERMAC "mactiger"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_TIGERMACBLOB "mactigerblob"
#endif
#endif

#if defined(__SHAKE128__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE128 "shake128"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE128BLOB "shake128blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE128MAC "macshake128"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE128MACBLOB "macshake128blob"
#endif
#endif

#if defined(__SHAKE256__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE256 "shake256"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE256BLOB "shake256blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE256MAC "macshake256"
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SHAKE256MACBLOB "macshake256blob"
#endif
#endif

#if defined(__SIPHASH64__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SIPHASH64 "siphash64"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SIPHASH64BLOB "siphash64blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SIPHASH64MAC "macsiphash64"
#endif
#endif


#if defined(__SIPHASH128__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SIPHASH128 "siphash128"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SIPHASH128BLOB "siphash128blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SIPHASH128MAC "macsiphash128"
#endif
#endif

#if defined(__LSH224__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_LSH224 "lsh224"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_LSH224BLOB "lsh224blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_LSH224MAC "maclsh224"
#endif
#endif

#if defined(__LSH256__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_LSH256 "lsh256"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_LSH256BLOB "lsh256blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_LSH256MAC "maclsh256"
#endif
#endif

#if defined(__LSH384__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_LSH384 "lsh384"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_LSH384BLOB "lsh384blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_LSH384MAC "maclsh384"
#endif
#endif



#if defined(__LSH512__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_LSH512 "lsh512"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_LSH512BLOB "lsh512blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_LSH512MAC "maclsh512"
#endif
#endif



#if defined(__SM3__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_SM3 "sm3"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_SM3BLOB "sm3blob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_SM3MAC "macsm3"
#endif
#endif

#if defined(__WHIRLPOOL__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_WHIRLPOOL "whirlpool"
#if defined(__USE_BLOB__)
#define HASH_SIZE_FUNCTION_NAME_WHIRLPOOLBLOB "whirlpoolblob"
#endif
#if defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_WHIRLPOOLMAC "macwhirlpool"
#endif
#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_CMACMAC "maccmac"
#endif
#if (defined(__CBCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_CBCMACMAC "maccbcmac"
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_DMACMAC "macdmac"
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_GMACMAC "macgmac"
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_HMACMAC "machmac"
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_POLY1305MACMAC "macpoly1305"
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_TWOTRACKMAC "mactwotrack"
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
#define HASH_SIZE_FUNCTION_NAME_VMACMAC "macvmac"
#endif


#define HASH_SIZE_MAX hash_size_hash_max

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

  rc = sqlite3_declare_vtab(db,"CREATE TABLE x(module_name,function_name,size)");
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
    char* error_message = NULL;
    hash_sizes_cursor *pCur = (hash_sizes_cursor*)cur;
    if (pCur->iRowid == 0)
    {
        // do nothing this should not happen and is a  placeholder for the if start
        //sqlite3_result_error(ctx, "Invalid Cursor Position", strlength("Invalid Cursor Position"));
        return SQLITE_OK;
    }
#if defined(__MD2__) || defined (__ALL__)
    else if( pCur->iRowid == hash_size_md2)
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD2), strlength(HASH_SIZE_FUNCTION_NAME_MD2), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_md2));
            break;
        }
    }
#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md2blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD2BLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD2BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md2));
            break;
        }
    }
#endif
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md2blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD2BLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD2BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md2));
            break;
        }
    }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_md2mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD2MAC), strlength(HASH_SIZE_FUNCTION_NAME_MD2MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md2));
            break;
        }
    }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md2macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD2MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD2MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md2));
            break;
        }
    }
#endif
#endif

#if defined(__MD4__) || defined (__ALL__)
    else if ( pCur->iRowid == hash_size_md4)
    {
        switch( i ){
            case HASH_SIZE_COLUMN_MODULE_NAME:
                sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
            case HASH_SIZE_COLUMN_FUNCTION_NAME:
                sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD4), strlength(HASH_SIZE_FUNCTION_NAME_MD4), free);
            break;
            case HASH_SIZE_COLUMN_HASH_SIZE:
                sqlite3_result_int(ctx,GetDigestSize(algo_md4));
            break;
        }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md4blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD4BLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD4BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md4));
            break;
        }
    }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_md4mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD4MAC), strlength(HASH_SIZE_FUNCTION_NAME_MD4MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md4));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md4macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD4MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD4MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md4));
            break;
        }
        }
#endif
#endif

#if defined(__MD5__) || defined (__ALL__)
#define HASH_SIZE_FUNCTION_NAME_MD5 "md5"
    else if (pCur->iRowid == hash_size_md5)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD5), strlength(HASH_SIZE_FUNCTION_NAME_MD5), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md5));
            break;
        }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md5blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD5BLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD5BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md5));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_md5mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD5MAC), strlength(HASH_SIZE_FUNCTION_NAME_MD5MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md5));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_md5macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_MD5MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_MD5MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_md5));
            break;
        }
        }
#endif
#endif

#if defined(__SHA1__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha1)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA1), strlength(HASH_SIZE_FUNCTION_NAME_SHA1), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha1));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha1blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA1BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA1BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha1));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha1mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA1MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA1MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha1));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha1macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA1MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA1MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha1));
            break;
        }
        }
#endif
#endif



#if defined(__SHA224__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha224)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA224), strlength(HASH_SIZE_FUNCTION_NAME_SHA224), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha224));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha224blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA224BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA224BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha224));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha224mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA224MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA224MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha224));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha224macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA224MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA224MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha224));
            break;
        }
        }
#endif
#endif


 
#if defined(__SHA256__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha256)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA256), strlength(HASH_SIZE_FUNCTION_NAME_SHA256), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha256));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha256blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA256BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA256BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha256mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA256MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA256MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha256macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA256MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA256MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha256));
            break;
        }
        }
#endif
#endif


#if defined(__SHA384__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha384)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA384), strlength(HASH_SIZE_FUNCTION_NAME_SHA384), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha384));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha384blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA384BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA384BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha384));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha384mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA384MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA384MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha384));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha384macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA384MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA384MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha384));
            break;
        }
        }
#endif
#endif



#if defined(__SHA512__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha512)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA512), strlength(HASH_SIZE_FUNCTION_NAME_SHA512), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha512));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha512blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA512BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA512BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha512));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha512mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA512MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA512MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha512));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)&& defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha512macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA512MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA512MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha512));
            break;
        }
        }
#endif
#endif


#if defined(__SHA3224__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha3224)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3224), strlength(HASH_SIZE_FUNCTION_NAME_SHA3224), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_224));
            break;
        }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3224blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3224BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3224BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_224));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha3224mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3224MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA3224MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_224));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3224macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3224MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3224MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_224));
            break;
        }
        }
#endif
#endif


#if defined(__SHA3256__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha3256)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3256), strlength(HASH_SIZE_FUNCTION_NAME_SHA3256), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_256));
            break;
        }
        }

#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3256blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3256BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3256BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha3256mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3256MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA3256MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3256macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3256MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3256MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_256));
            break;
        }
        }
#endif
#endif


#if defined(__SHA3384__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha3384)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3384), strlength(HASH_SIZE_FUNCTION_NAME_SHA3384), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_384));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3384blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3384BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3384BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_384));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha3384mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3384MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA3384MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_384));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3384macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3384MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3384MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_384));
            break;
        }
        }
#endif
#endif



#if defined(__SHA3512__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sha3512)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3512), strlength(HASH_SIZE_FUNCTION_NAME_SHA3512), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_512));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3512blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3512BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3512BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_512));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sha3512mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3512MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHA3512MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_512));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sha3512macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHA3512MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHA3512MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sha3_512));
            break;
        }
        }
#endif
#endif


#if defined(__RIPEMD128__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_ripemd128)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD128), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD128), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_128));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd128blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD128BLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD128BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_128));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_ripemd128mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD128MAC), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD128MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_128));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd128macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD128MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD128MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_128));
            break;
        }
        }
#endif

#endif



#if defined(__RIPEMD160__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_ripemd160)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD160), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD160), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_160));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd160blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD160BLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD160BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_160));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_ripemd160mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD160MAC), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD160MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_160));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd160macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD160MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD160MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_160));
            break;
        }
        }
#endif
#endif



#if defined(__RIPEMD256__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_ripemd256)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD256), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD256), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_256));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd256blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD256BLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD256BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_256));
            break;
        }
        }

#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_ripemd256mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD256MAC), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD256MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_256));
            break;
        }
        }

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd256macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD256MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD256MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_256));
            break;
        }
        }

#endif
#endif



#if defined(__RIPEMD320__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_ripemd320)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD320), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD320), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_320));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd320blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD320BLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD320BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_320));
            break;
        }
        }
#endif 
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_ripemd320mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD320MAC), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD320MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_320));
            break;
        }
        }
#endif 
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_ripemd320macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_RIPEMD320MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_RIPEMD320MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_ripemd_320));
            break;
        }
        }
#endif 
#endif


    
#if defined(__BLAKE2B__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_blake2b)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2B), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2B), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2b));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_blake2bblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2BBLOB), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2BBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2b));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_blake2bmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2BMAC), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2BMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2b));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_blake2bmacblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2BMACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2BMACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2b));
            break;
        }
        }
#endif
#endif



#if defined(__BLAKE2S__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_blake2s)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2S), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2S), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2s));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_blake2sblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2SBLOB), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2SBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2s));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_blake2smac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2SMAC), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2SMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2s));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_blake2smacblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_BLAKE2SMACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_BLAKE2SMACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_blake2s));
            break;
        }
        }
#endif
#endif
    
#if defined(__TIGER__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_tiger)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_TIGER), strlength(HASH_SIZE_FUNCTION_NAME_TIGER), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_tiger));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_tigerblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_TIGERBLOB), strlength(HASH_SIZE_FUNCTION_NAME_TIGERBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_tiger));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_tigermac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_TIGERMAC), strlength(HASH_SIZE_FUNCTION_NAME_TIGERMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_tiger));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_tigermacblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_TIGERMACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_TIGERMACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_tiger));
            break;
        }
        }
#endif
#endif


    
#if defined(__SHAKE128__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_shake128)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE128), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE128), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_128));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_shake128blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE128BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE128BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_128));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_shake128mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE128MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE128MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_128));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_shake128macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE128MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE128MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_128));
            break;
        }
        }
#endif
#endif



#if defined(__SHAKE256__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_shake256)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE256), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE256), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_256));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_shake256blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE256BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE256BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_shake256mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE256MAC), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE256MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_shake256macblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SHAKE256MACBLOB), strlength(HASH_SIZE_FUNCTION_NAME_SHAKE256MACBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_256));
            break;
        }
        }
#endif
#endif


    
#if defined(__SIPHASH64__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_siphash64)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SIPHASH64), strlength(HASH_SIZE_FUNCTION_NAME_SIPHASH64), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_siphash64blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SIPHASH64BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SIPHASH64BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_256));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_siphash64mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SIPHASH64MAC), strlength(HASH_SIZE_FUNCTION_NAME_SIPHASH64MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_shake_256));
            break;
        }
        }
#endif
#endif



#if defined(__SIPHASH128__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_siphash128)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SIPHASH128), strlength(HASH_SIZE_FUNCTION_NAME_SIPHASH128), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash128));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_siphash128blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SIPHASH128BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SIPHASH128BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash128));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_siphash128mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SIPHASH128MAC), strlength(HASH_SIZE_FUNCTION_NAME_SIPHASH128MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash128));
            break;
        }
        }
#endif
#endif


    
#if defined(__LSH224__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_lsh224)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH224), strlength(HASH_SIZE_FUNCTION_NAME_LSH224), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_lsh_224));
            break;
            }
    }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_lsh224blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH224BLOB), strlength(HASH_SIZE_FUNCTION_NAME_LSH224BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_lsh224mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH224MAC), strlength(HASH_SIZE_FUNCTION_NAME_LSH224MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#endif



#if defined(__LSH256__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_lsh256)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH256), strlength(HASH_SIZE_FUNCTION_NAME_LSH256), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_lsh_256));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_lsh256blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH256BLOB), strlength(HASH_SIZE_FUNCTION_NAME_LSH256BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_lsh256mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH256MAC), strlength(HASH_SIZE_FUNCTION_NAME_LSH256MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#endif



#if defined(__LSH384__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_lsh384)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH384), strlength(HASH_SIZE_FUNCTION_NAME_LSH384), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_lsh_384));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_lsh384blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH384BLOB), strlength(HASH_SIZE_FUNCTION_NAME_LSH384BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_lsh384mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH384MAC), strlength(HASH_SIZE_FUNCTION_NAME_LSH384MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#endif

#if defined(__LSH512__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_lsh512)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH512), strlength(HASH_SIZE_FUNCTION_NAME_LSH512), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_lsh_512));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_lsh512blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH512BLOB), strlength(HASH_SIZE_FUNCTION_NAME_LSH512BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_lsh512mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_LSH512MAC), strlength(HASH_SIZE_FUNCTION_NAME_LSH512MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#endif

#if defined(__SM3__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_sm3)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SM3), strlength(HASH_SIZE_FUNCTION_NAME_SM3), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sm3));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_sm3blob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SM3BLOB), strlength(HASH_SIZE_FUNCTION_NAME_SM3BLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_sm3mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_SM3MAC), strlength(HASH_SIZE_FUNCTION_NAME_SM3MAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif

#endif



#if defined(__WHIRLPOOL__) || defined (__ALL__)
    else if (pCur->iRowid == hash_size_whirlpool)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_WHIRLPOOL), strlength(HASH_SIZE_FUNCTION_NAME_WHIRLPOOL), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_whirlpool));
            break;
        }
        }
#if defined(__USE_BLOB__)
    else if (pCur->iRowid == hash_size_whirlpoolblob)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_WHIRLPOOLBLOB), strlength(HASH_SIZE_FUNCTION_NAME_WHIRLPOOLBLOB), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#if defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_whirlpoolmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_WHIRLPOOLMAC), strlength(HASH_SIZE_FUNCTION_NAME_WHIRLPOOLMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_sip_hash64));
            break;
        }
        }
#endif
#endif
#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_cmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_CMACMAC), strlength(HASH_SIZE_FUNCTION_NAME_CMACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_cmac));
            break;
        }
        }
#endif
#if (defined(__CBCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_cbcmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_CBCMACMAC), strlength(HASH_SIZE_FUNCTION_NAME_CBCMACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_cbc_mac));
            break;
        }
        }
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_dmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_DMACMAC), strlength(HASH_SIZE_FUNCTION_NAME_DMACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_dmac));
            break;
            }
        }

#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_gmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_GMACMAC), strlength(HASH_SIZE_FUNCTION_NAME_GMACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_gmac));
            break;
            }
        }

#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_hmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_HMACMAC), strlength(HASH_SIZE_FUNCTION_NAME_HMACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_hmac));
            break;
            }
        }
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_poly1305mac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_POLY1305MACMAC), strlength(HASH_SIZE_FUNCTION_NAME_POLY1305MACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_poly_1305));
            break;
            }
        }
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_twotrackmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_TWOTRACKMAC), strlength(HASH_SIZE_FUNCTION_NAME_TWOTRACKMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_two_track));
            break;
            }
        }
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
    else if (pCur->iRowid == hash_size_vmacmac)
    {
        switch (i) {
        case HASH_SIZE_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_MODULE_NAME), strlength(HASH_SIZE_MODULE_NAME), free);
            break;
        case HASH_SIZE_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_SIZE_FUNCTION_NAME_VMACMAC), strlength(HASH_SIZE_FUNCTION_NAME_VMACMAC), free);
            break;
        case HASH_SIZE_COLUMN_HASH_SIZE:
            sqlite3_result_int(ctx, GetDigestSize(algo_hmac_vmac));
            break;
        }
        }
#endif

    else
    {
        error_message = sqlite3_mprintf("Invalid Cursor Position: %lld", pCur->iRowid);
        if (error_message)
        {
            sqlite3_result_error(ctx, error_message, strlength(error_message));
            sqlite3_free(error_message);
        }
        else
        {
            sqlite3_result_error(ctx, "Invalid Cursor Position", strlength("Invalid Cursor Position"));
        }
        return SQLITE_ERROR;
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
    pIdxInfo->estimatedCost = (double)HASH_SIZE_MAX;
    pIdxInfo->estimatedRows = HASH_SIZE_MAX;
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
