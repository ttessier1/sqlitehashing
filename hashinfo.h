#pragma once 
//#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#ifndef SQLITE_OMIT_VIRTUALTABLE

#define HASH_INFO_MODULE_NAME "hashing"
enum hash_functions
{
    hash_function_hash_info = 1, // allways
    hash_function_hash_size, // allways
    hash_function_hash_ping, // allways
    hash_function_rot13, // allways
#if defined(__MD2__) || defined (__ALL__)
    hash_function_md2, // md2 enabled
#endif
#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_md2blob, // md2blob enabled
#endif
#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_md2mac, // md2mac enabled
#endif
#if (defined(__MD2__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_md2macblob, // md2mac enabled
#endif
#if defined(__MD4__) || defined (__ALL__)
    hash_function_md4, // md4 enabled
#endif
#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_md4blob, // md4blob enabled
#endif
#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_md4mac, // md4mac enabled
#endif
#if (defined(__MD4__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_md4macblob, // md4mac enabled
#endif
#if defined(__MD5__) || defined (__ALL__)
    hash_function_md5, // md5 enabled
#endif
#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_md5blob, // md5blob enabled
#endif
#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_md5mac, // md5mac enabled
#endif
#if (defined(__MD5__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_md5macblob, // md5mac enabled
#endif
#if defined(__SHA1__) || defined (__ALL__)
    hash_function_sha1, // sha1 enabled
#endif
#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha1blob, // mdsha1blob enabled
#endif
#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha1mac, // mdsha1mac enabled
#endif
#if (defined(__SHA1__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_sha1macblob, // mdsha1mac enabled
#endif
#if defined(__SHA224__) || defined (__ALL__)
    hash_function_sha224, // sha224 enabled
#endif
#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha224blob, // mdsha224blob enabled
#endif
#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha224mac, // mdsha224mac enabled
#endif
#if (defined(__SHA224__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_sha224macblob, // mdsha224mac enabled
#endif
#if defined(__SHA256__) || defined (__ALL__)
    hash_function_sha256, // sha256 enabled
#endif
#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha256blob, // mdsha256blob enabled
#endif

#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha256mac, // mdsha256mac enabled
#endif
#if (defined(__SHA256__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_sha256macblob, // mdsha256mac enabled
#endif
#if defined(__SHA384__) || defined (__ALL__)
    hash_function_sha384, // sha384 enabled
#endif
#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha384blob, // mdsha384blob enabled
#endif
#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha384mac, // mdsha384mac enabled
#endif
#if (defined(__SHA384__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_sha384macblob, // mdsha384mac enabled
#endif
#if defined(__SHA512__) || defined (__ALL__)
    hash_function_sha512, // sha512 enabled
#endif
#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha512blob, // mdsha512blob enabled
#endif
#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha512mac, // mdsha512mac enabled
#endif
#if (defined(__SHA512__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_sha512macblob, // mdsha512mac enabled
#endif
#if defined(__SHA3224__) || defined (__ALL__)
    hash_function_sha3224, // sha3224 enabled
#endif
#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha3224blob, // mdsha3224blob enabled
#endif
#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha3224mac, // mdsha3224mac enabled
#endif
#if (defined(__SHA3224__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_sha3224macblob, // mdsha3224mac enabled
#endif
#if defined(__SHA3256__) || defined (__ALL__)
    hash_function_sha3256, // sha3256 enabled
#endif
#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha3256blob, // mdsha3256blob enabled
#endif
#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sha3256mac, // mdsha3256mac enabled
#endif
#if (defined(__SHA3256__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_sha3256macblob, // mdsha3256mac enabled
#endif
#if defined(__SHA3384__) || defined (__ALL__)
    hash_function_sha3384, // sha3384 enabled
#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha3384blob, // mdsha384blob enabled
#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_sha3384mac, // mdsha384mac enabled
#endif
#if (defined(__SHA3384__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_sha3384macblob, // mdsha384mac enabled
#endif
#if defined(__SHA3512__) || defined (__ALL__)
    hash_function_sha3512, // sha3512 enabled
#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sha3512blob, // mdsha3512blob enabled
#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_sha3512mac, // mdsha3512mac enabled
#endif
#if (defined(__SHA3512__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_function_sha3512macblob, // mdsha3512mac enabled
#endif
#if defined(__RIPEMD128__) || defined (__ALL__)
    hash_function_ripemd128,
#endif
#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_ripemd128blob, 
#endif
#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_ripemd128mac,
#endif
#if (defined(__RIPEMD128__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_function_ripemd128macblob,
#endif
#if defined(__RIPEMD160__) || defined (__ALL__)
    hash_function_ripemd160,
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_ripemd160blob,
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_ripemd160mac,
#endif
#if (defined(__RIPEMD160__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_function_ripemd160macblob,
#endif
#if defined(__RIPEMD256__) || defined (__ALL__)
    hash_function_ripemd256,
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_ripemd256blob,
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_ripemd256mac,
#endif
#if (defined(__RIPEMD256__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
        hash_function_ripemd256macblob,
#endif
#if defined(__RIPEMD320__) || defined (__ALL__)
    hash_function_ripemd320,
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_ripemd320blob,
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_ripemd320mac,
#endif
#if (defined(__RIPEMD320__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_ripemd320macblob,
#endif
#if defined(__BLAKE2B__) || defined (__ALL__)
    hash_function_blake2b,
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_blake2bblob,
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_blake2bmac,
#endif
#if (defined(__BLAKE2B__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_blake2bmacblob,
#endif
#if defined(__BLAKE2S__) || defined (__ALL__)
        hash_function_blake2s,
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_blake2sblob,
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_blake2smac,
#endif
#if (defined(__BLAKE2S__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_blake2smacblob,
#endif
#if defined(__TIGER__) || defined (__ALL__)
        hash_function_tiger,
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_tigerblob,
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_tigermac,
#endif
#if (defined(__TIGER__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_tigermacblob,
#endif
#if defined(__SHAKE128__) || defined (__ALL__)
        hash_function_shake128,
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_shake128blob,
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_shake128mac,
#endif
#if (defined(__SHAKE128__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
            hash_function_shake128macblob,
#endif
#if defined(__SHAKE256__) || defined (__ALL__)
        hash_function_shake256,
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_shake256blob,
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_MAC__)
        hash_function_shake256mac,
#endif
#if (defined(__SHAKE256__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_shake256macblob,
#endif
#if defined(__SIPHASH64__) || defined (__ALL__)
        hash_function_siphash64,
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_siphash64blob,
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_siphash64mac,
#endif
#if (defined(__SIPHASH64__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_siphash64macblob,
#endif
#if defined(__SIPHASH128__) || defined (__ALL__)
        hash_function_siphash128,
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_siphash128blob,
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_siphash128mac,
#endif
#if (defined(__SIPHASH128__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_siphash128macblob,
#endif
#if defined(__LSH224__) || defined (__ALL__)
      hash_function_lsh224,
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_BLOB__)
      hash_function_lsh224blob,
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_MAC__)
      hash_function_lsh224mac,
#endif
#if (defined(__LSH224__) || defined (__ALL__)) && defined(__USE_MAC__ )&& defined(__USE_BLOB__)
      hash_function_lsh224macblob,
#endif
#if defined(__LSH256__) || defined (__ALL__)
        hash_function_lsh256,
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_BLOB__)
        hash_function_lsh256blob,
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_lsh256mac,
#endif
#if (defined(__LSH256__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_lsh256macblob,
#endif
#if defined(__LSH384__) || defined (__ALL__)
    hash_function_lsh384,
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_lsh384blob,
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_lsh384mac,
#endif
#if (defined(__LSH384__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_lsh384macblob,
#endif
#if defined(__LSH512__) || defined (__ALL__)
    hash_function_lsh512,
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_lsh512blob,
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_lsh512mac,
#endif
#if (defined(__LSH512__) || defined (__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)
    hash_function_lsh512macblob,
#endif
#if defined(__SM3__) || defined (__ALL__)
    hash_function_sm3,
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_sm3blob,
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_sm3mac,
#endif
#if (defined(__SM3__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_sm3macblob,
#endif
#if defined(__WHIRLPOOL__) || defined (__ALL__)
    hash_function_whirlpool,
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_BLOB__)
    hash_function_whirlpoolblob,
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_MAC__)
    hash_function_whirlpoolmac,
#endif
#if (defined(__WHIRLPOOL__) || defined (__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_whirlpoolmacblob,
#endif
#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_cmac,
#endif
#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_cmac_blob,
#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_cbcmac,
#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_cbcmac_blob,
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_dmac,
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_dmac_blob,
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_gmac,
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_gmac_blob,
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_hmac,
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_hmac_blob,
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_poly1305,
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
    hash_function_poly1305_blob,
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_twotrackmac,
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
            hash_function_twotrackmac_blob,
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
    hash_function_vmacmac,
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)
        hash_function_vmacmac_blob,
#endif

        hash_function_hash_max
};

#define HASH_INFO_FUNCTION_NAME_HASH_INFO "hash_info"
#define HASH_INFO_COLUMN_TYPE_HASH_INFO "table"
#define HASH_INFO_COLUMN_SIGNATURE_HASH_INFO "select * FROM hash_info();"
#define HASH_INFO_FUNCTION_VERSION_HASH_INFO "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_HASH_INFO "2024-01-19-01:01:01"

#define HASH_INFO_FUNCTION_NAME_HASH_SIZES "hash_sizes"
#define HASH_INFO_COLUMN_TYPE_HASH_SIZES "table"
#define HASH_INFO_COLUMN_SIGNATURE_HASH_SIZES "select * FROM hash_sizes();"
#define HASH_INFO_FUNCTION_VERSION_HASH_SIZES "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_HASH_SIZES "2024-01-19-01:01:01"

#define HASH_INFO_FUNCTION_NAME_HASH_PING "hash_ping"
#define HASH_INFO_COLUMN_SIGNATURE_HASH_PING "select hash_ping();"
#define HASH_INFO_COLUMN_TYPE_HASH_PING "util"
#define HASH_INFO_FUNCTION_VERSION_HASH_PING "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_HASH_PING "2024-01-19-01:01:01"

#define HASH_INFO_FUNCTION_NAME_ROT13 "rot13"
#define HASH_INFO_COLUMN_TYPE_ROT13 "transform"
#define HASH_INFO_COLUMN_SIGNATURE_ROT13 "select rot([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_ROT13 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_ROT13 "2024-01-19-01:01:01"

#if defined(__MD2__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_MD2 "md2"
#define HASH_INFO_COLUMN_TYPE_MD2 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD2 "select md2([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_MD2 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD2 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_MD2BLOB "md2blob"
#define HASH_INFO_COLUMN_TYPE_MD2BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD2BLOB "select md2blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_MD2BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD2BLOB "2024-06-10-01:01:01"
#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_MD2MAC "macmd2"
#define HASH_INFO_COLUMN_TYPE_MD2MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD2MAC "select macmd2([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_MD2MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD2MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_MD2MACBLOB "macmd2blob"
#define HASH_INFO_COLUMN_TYPE_MD2MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD2MACBLOB "select macmd2blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_MD2MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD2MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__MD4__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_MD4 "md4"
#define HASH_INFO_COLUMN_TYPE_MD4 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD4 "select md4([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_MD4 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD4 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_MD4BLOB "md4blob"
#define HASH_INFO_COLUMN_TYPE_MD4BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD4BLOB "select md4blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_MD4BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD4BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_MD4MAC "macmd4"
#define HASH_INFO_COLUMN_TYPE_MD4MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD4MAC "select macmd4([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_MD4MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD4MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_MD4MACBLOB "macmd4blob"
#define HASH_INFO_COLUMN_TYPE_MD4MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD4MACBLOB "select macmd4blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_MD4MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD4MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__MD5__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_MD5 "md5"
#define HASH_INFO_COLUMN_TYPE_MD5 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD5 "select md5([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_MD5 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD5 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_MD5BLOB "md5blob"
#define HASH_INFO_COLUMN_TYPE_MD5BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD5BLOB "select md5blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_MD5BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD5BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_MD5MAC "macmd5"
#define HASH_INFO_COLUMN_TYPE_MD5MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD5MAC "select macmd5([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_MD5MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD5MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_MD5MACBLOB "macmd5blob"
#define HASH_INFO_COLUMN_TYPE_MD5MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_MD5MACBLOB "select macmd5blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_MD5MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_MD5MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__SHA1__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA1 "sha1"
#define HASH_INFO_COLUMN_TYPE_SHA1 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA1 "select sha1([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA1 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA1 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA1BLOB "sha1blob"
#define HASH_INFO_COLUMN_TYPE_SHA1BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA1BLOB "select sha1blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA1BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA1BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA1MAC "macsha1"
#define HASH_INFO_COLUMN_TYPE_SHA1MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA1MAC "select macsha1([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA1MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA1MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA1MACBLOB "macsha1blob"
#define HASH_INFO_COLUMN_TYPE_SHA1MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA1MACBLOB "select macsha1blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA1MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA1MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__SHA224__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA224 "sha224"
#define HASH_INFO_COLUMN_TYPE_SHA224 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA224 "select sha224([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA224 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA224 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA224BLOB "sha224blob"
#define HASH_INFO_COLUMN_TYPE_SHA224BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA224BLOB "select sha224blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA224BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA224BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA224MAC "macsha224"
#define HASH_INFO_COLUMN_TYPE_SHA224MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA224MAC "select macsha224([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA224MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA224MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA224MACBLOB "macsha224blob"
#define HASH_INFO_COLUMN_TYPE_SHA224MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA224MACBLOB "select macsha224blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA224MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA224MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__SHA256__) || defined ( __ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA256 "sha256"
#define HASH_INFO_COLUMN_TYPE_SHA256 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA256 "select sha256([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA256 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA256 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA256BLOB "sha256blob"
#define HASH_INFO_COLUMN_TYPE_SHA256BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA256BLOB "select sha256blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA256BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA256BLOB "2024-06-10-01:01:01"

#endif 
#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA256MAC "macsha256"
#define HASH_INFO_COLUMN_TYPE_SHA256MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA256MAC "select macsha256([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA256MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA256MAC "2024-06-10-01:01:01"

#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA256MACBLOB "macsha256blob"
#define HASH_INFO_COLUMN_TYPE_SHA256MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA256MACBLOB "select macsha256blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA256MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA256MACBLOB "2024-06-10-01:01:01"

#endif 

#endif

#if defined(__SHA384__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA384 "sha384"
#define HASH_INFO_COLUMN_TYPE_SHA384 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA384 "select sha384([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA384 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA384 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA384BLOB "sha384blob"
#define HASH_INFO_COLUMN_TYPE_SHA384BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA384BLOB "select sha384blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA384BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA384BLOB "2024-06-10-01:01:01"

#endif


#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA384MAC "macsha384"
#define HASH_INFO_COLUMN_TYPE_SHA384MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA384MAC "select macsha384([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA384MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA384MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA384MACBLOB "macsha384blob"
#define HASH_INFO_COLUMN_TYPE_SHA384MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA384MACBLOB "select macsha384blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA384MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA384MACBLOB "2024-06-10-01:01:01"

#endif

#endif 

#if defined(__SHA512__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA512 "sha512"
#define HASH_INFO_COLUMN_TYPE_SHA512 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA512 "select sha512([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA512 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA512 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA512BLOB "sha512blob"
#define HASH_INFO_COLUMN_TYPE_SHA512BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA512BLOB "select sha512blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA512BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA512BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA512MAC "macsha512"
#define HASH_INFO_COLUMN_TYPE_SHA512MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA512MAC "select macsha512([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA512MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA512MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA512MACBLOB "macsha512blob"
#define HASH_INFO_COLUMN_TYPE_SHA512MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA512MACBLOB "select macsha512blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA512MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA512MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__SHA3224__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA3224 "sha3224"
#define HASH_INFO_COLUMN_TYPE_SHA3224 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3224 "select sha3224([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3224 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3224 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3224BLOB "sha3224blob"
#define HASH_INFO_COLUMN_TYPE_SHA3224BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3224BLOB "select sha3224blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3224BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3224BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA3224MAC "macsha3224"
#define HASH_INFO_COLUMN_TYPE_SHA3224MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3224MAC "select macsha3224([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3224MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3224MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3224MACBLOB "macsha3224blob"
#define HASH_INFO_COLUMN_TYPE_SHA3224MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3224MACBLOB "select macsha3224blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3224MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3224MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__SHA3256__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA3256 "sha3256"
#define HASH_INFO_COLUMN_TYPE_SHA3256 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3256 "select sha3256([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3256 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3256 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3256BLOB "sha3256blob"
#define HASH_INFO_COLUMN_TYPE_SHA3256BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3256BLOB "select sha3256blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3256BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3256BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA3256MAC "macsha3256"
#define HASH_INFO_COLUMN_TYPE_SHA3256MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3256MAC "select macsha3256([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3256MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3256MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3256MACBLOB "macsha3256blob"
#define HASH_INFO_COLUMN_TYPE_SHA3256MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3256MACBLOB "select macsha3256blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3256MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3256MACBLOB "2024-06-10-01:01:01"

#endif


#endif


#if defined(__SHA3384__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA3384 "sha3384"
#define HASH_INFO_COLUMN_TYPE_SHA3384 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3384 "select sha3384([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3384 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3384 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3384BLOB "sha3384blob"
#define HASH_INFO_COLUMN_TYPE_SHA3384BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3384BLOB "select sha3384blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3384BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3384BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA3384MAC "macsha3384"
#define HASH_INFO_COLUMN_TYPE_SHA3384MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3384MAC "select macsha3384([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3384MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3384MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3384MACBLOB "macsha3384blob"
#define HASH_INFO_COLUMN_TYPE_SHA3384MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3384MACBLOB "select macsha3384blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3384MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3384MACBLOB "2024-06-10-01:01:01"

#endif

#endif



#if defined(__SHA3512__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHA3512 "sha3512"
#define HASH_INFO_COLUMN_TYPE_SHA3512 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3512 "select sha3512([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3512 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3512 "2024-01-19-01:01:01"

#if  defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3512BLOB "sha3512blob"
#define HASH_INFO_COLUMN_TYPE_SHA3512BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3512BLOB "select sha3512blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3512BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3512BLOB "2024-06-10-01:01:01"

#endif

#if  defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHA3512MAC "macsha3512"
#define HASH_INFO_COLUMN_TYPE_SHA3512MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3512MAC "select macsha3512([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3512MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3512MAC "2024-06-10-01:01:01"

#endif

#if  defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHA3512MACBLOB "macsha3512blob"
#define HASH_INFO_COLUMN_TYPE_SHA3512MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHA3512MACBLOB "select macsha3512blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHA3512MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHA3512MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__RIPEMD128__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD128 "ripemd128"
#define HASH_INFO_COLUMN_TYPE_RIPEMD128 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD128 "select ripemd128([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD128 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD128 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD128BLOB "ripemd128blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD128BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD128BLOB "select ripemd128blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD128BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD128BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD128MAC "macripemd128"
#define HASH_INFO_COLUMN_TYPE_RIPEMD128MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD128MAC "select macripemd128([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD128MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD128MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD128MACBLOB "macripemd128blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD128MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD128MACBLOB "select macripemd128blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD128MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD128MACBLOB "2024-06-10-01:01:01"

#endif


#endif

#if defined(__RIPEMD160__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD160 "ripemd160"
#define HASH_INFO_COLUMN_TYPE_RIPEMD160 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD160 "select ripemd160([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD160 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD160 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD160BLOB "ripemd160blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD160BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD160BLOB "select ripemd160blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD160BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD160BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD160MAC "macripemd160"
#define HASH_INFO_COLUMN_TYPE_RIPEMD160MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD160MAC "select macripemd160([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD160MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD160MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD160MACBLOB "macripemd160blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD160MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD160MACBLOB "select macripemd160blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD160MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD160MACBLOB "2024-06-10-01:01:01"

#endif

#endif



#if defined(__RIPEMD256__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD256 "ripemd256"
#define HASH_INFO_COLUMN_TYPE_RIPEMD256 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD256 "select ripemd256([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD256 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD256 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD256BLOB "ripemd256blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD256BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD256BLOB "select ripemd256blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD256BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD256BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD256MAC "macripemd256"
#define HASH_INFO_COLUMN_TYPE_RIPEMD256MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD256MAC "select macripemd256([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD256MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD256MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) &&  defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD256MACBLOB "macripemd256blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD256MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD256MACBLOB "select macripemd256blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD256MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD256MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__RIPEMD320__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD320 "ripemd320"
#define HASH_INFO_COLUMN_TYPE_RIPEMD320 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD320 "select ripemd320([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD320 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD320 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD320BLOB "ripemd320blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD320BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD320BLOB "select ripemd320blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD320BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD320BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD320MAC "macripemd320"
#define HASH_INFO_COLUMN_TYPE_RIPEMD320MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD320MAC "select macripemd320([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD320MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD320MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_RIPEMD320MACBLOB "macripemd320blob"
#define HASH_INFO_COLUMN_TYPE_RIPEMD320MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_RIPEMD320MACBLOB "select macripemd320blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_RIPEMD320MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_RIPEMD320MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__BLAKE2B__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2B "blake2b"
#define HASH_INFO_COLUMN_TYPE_BLAKE2B "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2B "select blake2b([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2B "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2B "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2BBLOB "blake2bblob"
#define HASH_INFO_COLUMN_TYPE_BLAKE2BBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2BBLOB "select blake2bblob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2BBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2BBLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2BMAC "macblake2b"
#define HASH_INFO_COLUMN_TYPE_BLAKE2BMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2BMAC "select macblake2b([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2BMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2BMAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2BMACBLOB "macblake2bblob"
#define HASH_INFO_COLUMN_TYPE_BLAKE2BMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2BMACBLOB "select macblake2bblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2BMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2BMACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__BLAKE2S__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2S "blake2s"
#define HASH_INFO_COLUMN_TYPE_BLAKE2S "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2S "select blake2s([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2S "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2S "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2SBLOB "blake2sblob"
#define HASH_INFO_COLUMN_TYPE_BLAKE2SBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2SBLOB "select blake2sblob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2SBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2SBLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2SMACBLOB "macblake2sblob"
#define HASH_INFO_COLUMN_TYPE_BLAKE2SMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2SMACBLOB "select macblake2sblob([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2SMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2SMACBLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_BLAKE2SMAC "macblake2s"
#define HASH_INFO_COLUMN_TYPE_BLAKE2SMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_BLAKE2SMAC "select macblake2s([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_BLAKE2SMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_BLAKE2SMAC "2024-06-10-01:01:01"

#endif

#endif 

#if defined(__TIGER__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_TIGER "tiger"
#define HASH_INFO_COLUMN_TYPE_TIGER "hash"
#define HASH_INFO_COLUMN_SIGNATURE_TIGER "select tiger([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_TIGER "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_TIGER "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_TIGERBLOB "tigerblob"
#define HASH_INFO_COLUMN_TYPE_TIGERBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_TIGERBLOB "select tigerblob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_TIGERBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_TIGERBLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_TIGERMAC "mactiger"
#define HASH_INFO_COLUMN_TYPE_TIGERMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_TIGERMAC "select mactiger([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_TIGERMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_TIGERMAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_TIGERMACBLOB "mactigerblob"
#define HASH_INFO_COLUMN_TYPE_TIGERMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_TIGERMACBLOB "select mactigerblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_TIGERMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_TIGERMACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__SHAKE128__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHAKE128 "shake128"
#define HASH_INFO_COLUMN_TYPE_SHAKE128 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE128 "select shake128([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE128 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE128 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHAKE128BLOB "shake128blob"
#define HASH_INFO_COLUMN_TYPE_SHAKE128BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE128BLOB "select shake128blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE128BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE128BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHAKE128MAC "macshake128"
#define HASH_INFO_COLUMN_TYPE_SHAKE128MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE128MAC "select macshake128([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE128MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE128MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHAKE128MACBLOB "macshake128blob"
#define HASH_INFO_COLUMN_TYPE_SHAKE128MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE128MACBLOB "select macshake128blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE128MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE128MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__SHAKE256__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SHAKE256 "shake256"
#define HASH_INFO_COLUMN_TYPE_SHAKE256 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE256 "select shake256([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE256 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE256 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHAKE256BLOB "shake256blob"
#define HASH_INFO_COLUMN_TYPE_SHAKE256BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE256BLOB "select shake256blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE256BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE256BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SHAKE256MAC "macshake256"
#define HASH_INFO_COLUMN_TYPE_SHAKE256MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE256MAC "select macshake256([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE256MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE256MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SHAKE256MACBLOB "macshake256blob"
#define HASH_INFO_COLUMN_TYPE_SHAKE256MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SHAKE256MACBLOB "select macshake256blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SHAKE256MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SHAKE256MACBLOB "2024-06-10-01:01:01"

#endif

#endif


#if defined(__SIPHASH64__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH64 "siphash64"
#define HASH_INFO_COLUMN_TYPE_SIPHASH64 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH64 "select siphash64([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH64 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH64 "2024-01-19-01:01:01"

#if  defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH64BLOB "siphash64blob"
#define HASH_INFO_COLUMN_TYPE_SIPHASH64BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH64BLOB "select siphash64blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH64BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH64BLOB "2024-06-10-01:01:01"

#endif

#if  defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH64MAC "macsiphash64"
#define HASH_INFO_COLUMN_TYPE_SIPHASH64MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH64MAC "select macsiphash64([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH64MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH64MAC "2024-06-10-01:01:01"

#endif

#if  defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH64MACBLOB "macsiphash64blob"
#define HASH_INFO_COLUMN_TYPE_SIPHASH64MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH64MACBLOB "select macsiphash64blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH64MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH64MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__SIPHASH128__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH128 "siphash128"
#define HASH_INFO_COLUMN_TYPE_SIPHASH128 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH128 "select siphash128([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH128 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH128 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH128BLOB "siphash128blob"
#define HASH_INFO_COLUMN_TYPE_SIPHASH128BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH128BLOB "select siphash128blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH128BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH128BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH128MAC "macsiphash128"
#define HASH_INFO_COLUMN_TYPE_SIPHASH128MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH128MAC "select macsiphash128([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH128MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH128MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SIPHASH128MACBLOB "macsiphash128blob"
#define HASH_INFO_COLUMN_TYPE_SIPHASH128MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SIPHASH128MACBLOB "select macsiphash128blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SIPHASH128MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SIPHASH128MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__LSH224__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_LSH224 "lsh224"
#define HASH_INFO_COLUMN_TYPE_LSH224 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH224 "select lsh224([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_LSH224 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH224 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH224BLOB "lsh224blob"
#define HASH_INFO_COLUMN_TYPE_LSH224BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH224BLOB "select lsh224blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_LSH224BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH224BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_LSH224MAC "maclsh224"
#define HASH_INFO_COLUMN_TYPE_LSH224MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH224MAC "select maclsh224([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH224MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH224MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH224MACBLOB "maclsh224blob"
#define HASH_INFO_COLUMN_TYPE_LSH224MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH224MACBLOB "select maclsh224blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH224MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH224MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__LSH256__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_LSH256 "lsh256"
#define HASH_INFO_COLUMN_TYPE_LSH256 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH256 "select lsh256([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_LSH256 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH256 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH256BLOB "lsh256blob"
#define HASH_INFO_COLUMN_TYPE_LSH256BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH256BLOB "select lsh256blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_LSH256BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH256BLOB "2024-06-10-01:01:01"

#endif 

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_LSH256MAC "maclsh256"
#define HASH_INFO_COLUMN_TYPE_LSH256MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH256MAC "select maclsh256([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH256MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH256MAC "2024-06-10-01:01:01"

#endif 

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH256MACBLOB "maclsh256blob"
#define HASH_INFO_COLUMN_TYPE_LSH256MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH256MACBLOB "select maclsh256blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH256MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH256MACBLOB "2024-06-10-01:01:01"

#endif 

#endif


#if defined(__LSH384__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_LSH384 "lsh384"
#define HASH_INFO_COLUMN_TYPE_LSH384 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH384 "select lsh384([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_LSH384 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH384 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH384BLOB "lsh384blob"
#define HASH_INFO_COLUMN_TYPE_LSH384BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH384BLOB "select lsh384blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_LSH384BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH384BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_LSH384MAC "maclsh384"
#define HASH_INFO_COLUMN_TYPE_LSH384MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH384MAC "select maclsh384([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH384MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH384MAC "2024-06-10-01:01:01"

#endif


#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH384MACBLOB "maclsh384blob"
#define HASH_INFO_COLUMN_TYPE_LSH384MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH384MACBLOB "select maclsh384blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH384MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH384MACBLOB "2024-06-10-01:01:01"

#endif

#endif



#if defined(__LSH512__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_LSH512 "lsh512"
#define HASH_INFO_COLUMN_TYPE_LSH512 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH512 "select lsh512([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_LSH512 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH512 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH512BLOB "lsh512blob"
#define HASH_INFO_COLUMN_TYPE_LSH512BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH512BLOB "select lsh512blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_LSH512BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH512BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_LSH512MAC "maclsh512"
#define HASH_INFO_COLUMN_TYPE_LSH512MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH512MAC "select maclsh512([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH512MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH512MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_LSH512MACBLOB "maclsh512blob"
#define HASH_INFO_COLUMN_TYPE_LSH512MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_LSH512MACBLOB "select maclsh512blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_LSH512MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_LSH512MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__SM3__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_SM3 "sm3"
#define HASH_INFO_COLUMN_TYPE_SM3 "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SM3 "select sm3([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_SM3 "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SM3 "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SM3BLOB "sm3blob"
#define HASH_INFO_COLUMN_TYPE_SM3BLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SM3BLOB "select sm3blob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_SM3BLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SM3BLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_SM3MAC "macsm3"
#define HASH_INFO_COLUMN_TYPE_SM3MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SM3MAC "select macsm3([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SM3MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SM3MAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_SM3MACBLOB "macsm3blob"
#define HASH_INFO_COLUMN_TYPE_SM3MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_SM3MACBLOB "select macsm3blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_SM3MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_SM3MACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if defined(__WHIRLPOOL__) || defined (__ALL__)

#define HASH_INFO_FUNCTION_NAME_WHIRLPOOL "whirlpool"
#define HASH_INFO_COLUMN_TYPE_WHIRLPOOL "hash"
#define HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOL "select whirlpool([stringtohash]);"
#define HASH_INFO_FUNCTION_VERSION_WHIRLPOOL "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_WHIRLPOOL "2024-01-19-01:01:01"

#if defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_WHIRLPOOLBLOB "whirlpoolblob"
#define HASH_INFO_COLUMN_TYPE_WHIRLPOOLBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLBLOB "select whirlpoolblob([database],[table],[column],[rowid]);"
#define HASH_INFO_FUNCTION_VERSION_WHIRLPOOLBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_WHIRLPOOLBLOB "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_WHIRLPOOLMAC "macwhirlpool"
#define HASH_INFO_COLUMN_TYPE_WHIRLPOOLMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLMAC "select macwhirlpool([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_WHIRLPOOLMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_WHIRLPOOLMAC "2024-06-10-01:01:01"

#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_WHIRLPOOLMACBLOB "macwhirlpoolblob"
#define HASH_INFO_COLUMN_TYPE_WHIRLPOOLMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLMACBLOB "select macwhirlpoolblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_WHIRLPOOLMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_WHIRLPOOLMACBLOB "2024-06-10-01:01:01"

#endif

#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_CMACMAC "maccmac"
#define HASH_INFO_COLUMN_TYPE_CMACMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_CMACMAC "select maccmac([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_CMACMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_CMACMAC "2024-06-10-01:01:01"

#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_CMACMACBLOB "maccmacblob"
#define HASH_INFO_COLUMN_TYPE_CMACMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_CMACMACBLOB "select maccmacblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_CMACMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_CMACMACBLOB "2024-06-10-01:01:01"

#endif

#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_CBCMACMAC "maccbcmac"
#define HASH_INFO_COLUMN_TYPE_CBCMACMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_CBCMACMAC "select maccbcmac([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_CBCMACMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_CBCMACMAC "2024-06-10-01:01:01"

#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__) && defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_CBCMACMACBLOB "maccbcmacblob"
#define HASH_INFO_COLUMN_TYPE_CBCMACMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_CBCMACMACBLOB "select maccbcmacblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_CBCMACMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_CBCMACMACBLOB "2024-06-10-01:01:01"

#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_DMACMAC "macdmac"
#define HASH_INFO_COLUMN_TYPE_DMACMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_DMACMAC "select macdmac([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_DMACMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_DMACMAC "2024-06-10-01:01:01"

#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_DMACMACBLOB "macdmac"
#define HASH_INFO_COLUMN_TYPE_DMACMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_DMACMACBLOB "select macdmac([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_DMACMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_DMACMACBLOB "2024-06-10-01:01:01"

#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_GMACMAC "macgmac"
#define HASH_INFO_COLUMN_TYPE_GMACMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_GMACMAC "select macgmac([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_GMACMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_GMACMAC "2024-06-10-01:01:01"

#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_GMACMACBLOB "macgmacblob"
#define HASH_INFO_COLUMN_TYPE_GMACMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_GMACMACBLOB "select macgmacblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_GMACMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_GMACMACBLOB "2024-06-10-01:01:01"

#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_HMACMAC "machmac"
#define HASH_INFO_COLUMN_TYPE_HMACMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_HMACMAC "select machmac([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_HMACMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_HMACMAC "2024-06-10-01:01:01"

#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_HMACMACBLOB "machmacblob"
#define HASH_INFO_COLUMN_TYPE_HMACMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_HMACMACBLOB "select machmacblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_HMACMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_HMACMACBLOB "2024-06-10-01:01:01"

#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_POLY1305MAC "macpoly1305"
#define HASH_INFO_COLUMN_TYPE_POLY1305MAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_POLY1305MAC "select macpoly1305([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_POLY1305MAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_POLY1305MAC "2024-06-10-01:01:01"

#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_POLY1305MACBLOB "macpoly1305blob"
#define HASH_INFO_COLUMN_TYPE_POLY1305MACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_POLY1305MACBLOB "select macpoly1305blob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_POLY1305MACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_POLY1305MACBLOB "2024-06-10-01:01:01"

#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_TWOTRACKMAC "mactwotrack"
#define HASH_INFO_COLUMN_TYPE_TWOTRACKMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_TWOTRACKMAC "select mactwotrack([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_TWOTRACKMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_TWOTRACKMAC "2024-06-10-01:01:01"

#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_TWOTRACKMACBLOB "mactwotrackblob"
#define HASH_INFO_COLUMN_TYPE_TWOTRACKMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_TWOTRACKMACBLOB "select mactwotrackblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_TWOTRACKMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_TWOTRACKMACBLOB "2024-06-10-01:01:01"

#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)

#define HASH_INFO_FUNCTION_NAME_VMACMAC "macvmac"
#define HASH_INFO_COLUMN_TYPE_VMACMAC "hash"
#define HASH_INFO_COLUMN_SIGNATURE_VMACMAC "select macvmac([stringtohash],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_VMACMAC "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_VMACMAC "2024-06-10-01:01:01"

#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&& defined(__USE_BLOB__)

#define HASH_INFO_FUNCTION_NAME_VMACMACBLOB "macvmacblob"
#define HASH_INFO_COLUMN_TYPE_VMACMACBLOB "hash"
#define HASH_INFO_COLUMN_SIGNATURE_VMACMACBLOB "select macvmacblob([database],[table],[column],[rowid],[key],[use_hex_key=1,use_as_is=0]);"
#define HASH_INFO_FUNCTION_VERSION_VMACMACBLOB "0.0.0.1"
#define HASH_INFO_FUNCTION_DATE_VMACMACBLOB "2024-06-10-01:01:01"

#endif

#define HASH_INFO_MAX hash_function_hash_max

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
    rc = sqlite3_declare_vtab(db,"CREATE TABLE x(module_name,function_name,type,signature,version,datecreated)");
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
  char* sqlite_text = NULL;
  if( pCur->iRowid == hash_function_hash_info)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_HASH_INFO), strlength(HASH_INFO_FUNCTION_NAME_HASH_INFO), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_HASH_INFO), strlength(HASH_INFO_COLUMN_TYPE_HASH_INFO), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_HASH_INFO), strlength(HASH_INFO_COLUMN_SIGNATURE_HASH_INFO), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_HASH_INFO), strlength(HASH_INFO_FUNCTION_VERSION_HASH_INFO), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_HASH_INFO), strlength(HASH_INFO_FUNCTION_DATE_HASH_INFO), free);
        break;
    }
  }
  else if( pCur->iRowid == hash_function_hash_size)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_HASH_SIZES), strlength(HASH_INFO_FUNCTION_NAME_HASH_SIZES), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_HASH_SIZES), strlength(HASH_INFO_COLUMN_TYPE_HASH_SIZES), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_HASH_SIZES), strlength(HASH_INFO_COLUMN_SIGNATURE_HASH_SIZES), free);
        break;

        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_HASH_SIZES), strlength(HASH_INFO_FUNCTION_VERSION_HASH_SIZES), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_HASH_SIZES), strlength(HASH_INFO_FUNCTION_DATE_HASH_SIZES), free);
        break;
    }
  }
  else if( pCur->iRowid == hash_function_hash_ping)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_HASH_PING), strlength(HASH_INFO_FUNCTION_NAME_HASH_PING), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_HASH_PING), strlength(HASH_INFO_COLUMN_TYPE_HASH_PING), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_HASH_PING), strlength(HASH_INFO_COLUMN_SIGNATURE_HASH_PING), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_HASH_PING), strlength(HASH_INFO_FUNCTION_VERSION_HASH_PING), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_HASH_PING), strlength(HASH_INFO_FUNCTION_DATE_HASH_PING), free);
        break;
    }
  }
  else if( pCur->iRowid == hash_function_rot13)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_ROT13), strlength(HASH_INFO_FUNCTION_NAME_ROT13), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_ROT13), strlength(HASH_INFO_COLUMN_TYPE_ROT13), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_ROT13), strlength(HASH_INFO_COLUMN_SIGNATURE_ROT13), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_ROT13), strlength(HASH_INFO_FUNCTION_VERSION_ROT13), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_ROT13), strlength(HASH_INFO_FUNCTION_DATE_ROT13), free);
        break;
    }
  }
#if defined(__MD2__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_md2)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD2), strlength(HASH_INFO_FUNCTION_NAME_MD2), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD2), strlength(HASH_INFO_COLUMN_TYPE_MD2), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD2), strlength(HASH_INFO_COLUMN_SIGNATURE_MD2), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD2), strlength(HASH_INFO_FUNCTION_VERSION_MD2), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD2), strlength(HASH_INFO_FUNCTION_DATE_MD2), free);
        break;
    }
  }
  #if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_md2blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD2BLOB), strlength(HASH_INFO_FUNCTION_NAME_MD2BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD2BLOB), strlength(HASH_INFO_COLUMN_TYPE_MD2BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD2BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_MD2BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD2BLOB), strlength(HASH_INFO_FUNCTION_VERSION_MD2BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD2BLOB), strlength(HASH_INFO_FUNCTION_DATE_MD2BLOB), free);
          break;
      }
  }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_md2macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD2MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_MD2MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD2MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_MD2MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD2MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_MD2MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD2MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_MD2MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD2MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_MD2MACBLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_md2mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD2MAC), strlength(HASH_INFO_FUNCTION_NAME_MD2MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD2MAC), strlength(HASH_INFO_COLUMN_TYPE_MD2MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD2MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_MD2MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD2MAC), strlength(HASH_INFO_FUNCTION_VERSION_MD2MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD2MAC), strlength(HASH_INFO_FUNCTION_DATE_MD2MAC), free);
          break;
      }
      }
#endif
#endif
#if defined(__MD4__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_md4)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD4), strlength(HASH_INFO_FUNCTION_NAME_MD4), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD4), strlength(HASH_INFO_COLUMN_TYPE_MD4), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD4), strlength(HASH_INFO_COLUMN_SIGNATURE_MD4), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD4), strlength(HASH_INFO_FUNCTION_VERSION_MD4), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD4), strlength(HASH_INFO_FUNCTION_DATE_MD4), free);
        break;
    }
  }
#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_md4blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD4BLOB), strlength(HASH_INFO_FUNCTION_NAME_MD4BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD4BLOB), strlength(HASH_INFO_COLUMN_TYPE_MD4BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD4BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_MD4BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD4BLOB), strlength(HASH_INFO_FUNCTION_VERSION_MD4BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD4BLOB), strlength(HASH_INFO_FUNCTION_DATE_MD4BLOB), free);
          break;
      }
      }
#endif

#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_md4mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD4MAC), strlength(HASH_INFO_FUNCTION_NAME_MD4MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD4MAC), strlength(HASH_INFO_COLUMN_TYPE_MD4MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD4MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_MD4MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD4MAC), strlength(HASH_INFO_FUNCTION_VERSION_MD4MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD4MAC), strlength(HASH_INFO_FUNCTION_DATE_MD4MAC), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_md4macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD4MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_MD4MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD4MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_MD4MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD4MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_MD4MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD4MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_MD4MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD4MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_MD4MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__MD5__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_md5)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD5), strlength(HASH_INFO_FUNCTION_NAME_MD5), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD5), strlength(HASH_INFO_COLUMN_TYPE_MD5), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD5), strlength(HASH_INFO_COLUMN_SIGNATURE_MD5), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD5), strlength(HASH_INFO_FUNCTION_VERSION_MD5), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD5), strlength(HASH_INFO_FUNCTION_DATE_MD5), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_md5blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD5BLOB), strlength(HASH_INFO_FUNCTION_NAME_MD5BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD5BLOB), strlength(HASH_INFO_COLUMN_TYPE_MD5BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD5BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_MD5BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD5BLOB), strlength(HASH_INFO_FUNCTION_VERSION_MD5BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD5BLOB), strlength(HASH_INFO_FUNCTION_DATE_MD5BLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_md5mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD5MAC), strlength(HASH_INFO_FUNCTION_NAME_MD5MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD5MAC), strlength(HASH_INFO_COLUMN_TYPE_MD5MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD5MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_MD5MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD5MAC), strlength(HASH_INFO_FUNCTION_VERSION_MD5MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD5MAC), strlength(HASH_INFO_FUNCTION_DATE_MD5MAC), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_md5macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_MD5MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_MD5MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_MD5MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_MD5MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_MD5MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_MD5MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_MD5MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_MD5MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_MD5MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_MD5MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__SHA1__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha1)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA1), strlength(HASH_INFO_FUNCTION_NAME_SHA1), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA1), strlength(HASH_INFO_COLUMN_TYPE_SHA1), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA1), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA1), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA1), strlength(HASH_INFO_FUNCTION_VERSION_SHA1), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA1), strlength(HASH_INFO_FUNCTION_DATE_SHA1), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha1blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA1BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA1BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA1BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA1BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA1BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA1BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA1BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA1BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA1BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA1BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha1mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA1MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA1MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA1MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA1MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA1MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA1MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA1MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA1MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA1MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA1MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha1macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA1MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA1MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA1MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA1MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA1MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA1MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA1MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA1MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA1MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA1MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__SHA224__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha224)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA224), strlength(HASH_INFO_FUNCTION_NAME_SHA224), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA224), strlength(HASH_INFO_COLUMN_TYPE_SHA224), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA224), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA224), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA224), strlength(HASH_INFO_FUNCTION_VERSION_SHA224), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA224), strlength(HASH_INFO_FUNCTION_DATE_SHA224), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha224blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA224BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA224BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA224BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA224BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA224BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA224BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA224BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA224BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA224BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA224BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha224mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA224MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA224MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA224MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA224MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA224MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA224MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA224MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA224MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA224MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA224MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha224macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA224MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA224MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA224MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA224MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA224MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA224MACBLOB), free);
          break;
      }
      }
#endif

#endif

#if defined(__SHA256__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha256)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA256), strlength(HASH_INFO_FUNCTION_NAME_SHA256), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA256), strlength(HASH_INFO_COLUMN_TYPE_SHA256), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA256), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA256), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA256), strlength(HASH_INFO_FUNCTION_VERSION_SHA256), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA256), strlength(HASH_INFO_FUNCTION_DATE_SHA256), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha256blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA256BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA256BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA256BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA256BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA256BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA256BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA256BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA256BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA256BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA256BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha256mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA256MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA256MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA256MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA256MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA256MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA256MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA256MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA256MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA256MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA256MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha256macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA256MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA256MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA256MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA256MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA256MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA256MACBLOB), free);
          break;
      }
      }
#endif
#endif
 
#if defined(__SHA384__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_sha384)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA384), strlength(HASH_INFO_FUNCTION_NAME_SHA384), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA384), strlength(HASH_INFO_COLUMN_TYPE_SHA384), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA384), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA384), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA384), strlength(HASH_INFO_FUNCTION_VERSION_SHA384), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA384), strlength(HASH_INFO_FUNCTION_DATE_SHA384), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha384blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA384BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA384BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA384BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA384BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA384BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA384BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA384BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA384BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA384BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA384BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha384mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA384MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA384MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA384MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA384MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA384MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA384MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA384MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA384MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA384MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA384MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha384macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA384MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA384MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA384MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA384MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA384MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA384MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__SHA512__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha512)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA512), strlength(HASH_INFO_FUNCTION_NAME_SHA512), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA512), strlength(HASH_INFO_COLUMN_TYPE_SHA512), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA512), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA512), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA512), strlength(HASH_INFO_FUNCTION_VERSION_SHA512), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA512), strlength(HASH_INFO_FUNCTION_DATE_SHA512), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha512blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA512BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA512BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA512BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA512BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA512BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA512BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA512BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA512BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA512BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA512BLOB), free);
          break;
      }
      }
#endif

#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha512mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA512MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA512MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA512MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA512MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA512MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA512MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA512MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA512MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA512MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA512MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha512macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA512MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA512MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA512MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA512MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA512MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA512MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__SHA3224__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha3224)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3224), strlength(HASH_INFO_FUNCTION_NAME_SHA3224), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3224), strlength(HASH_INFO_COLUMN_TYPE_SHA3224), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3224), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3224), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3224), strlength(HASH_INFO_FUNCTION_VERSION_SHA3224), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3224), strlength(HASH_INFO_FUNCTION_DATE_SHA3224), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3224blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3224BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3224BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3224BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3224BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3224BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3224BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3224BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3224BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3224BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3224BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha3224mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3224MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA3224MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3224MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA3224MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3224MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3224MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3224MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA3224MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3224MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA3224MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3224macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3224MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3224MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3224MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3224MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3224MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3224MACBLOB), free);
          break;
      }
      }
#endif
#endif
#if defined(__SHA3256__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha3256)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3256), strlength(HASH_INFO_FUNCTION_NAME_SHA3256), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3256), strlength(HASH_INFO_COLUMN_TYPE_SHA3256), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3256), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3256), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3256), strlength(HASH_INFO_FUNCTION_VERSION_SHA3256), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3256), strlength(HASH_INFO_FUNCTION_DATE_SHA3256), free);
        break;
    }
  }
#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3256blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3256BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3256BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3256BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3256BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3256BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3256BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3256BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3256BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3256BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3256BLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha3256mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3256MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA3256MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3256MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA3256MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3256MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3256MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3256MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA3256MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3256MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA3256MAC), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha3256macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3256MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3256MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3256MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3256MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3256MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3256MACBLOB), free);
          break;
      }
      }
#endif
#endif
#if defined(__SHA3384__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha3384)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3384), strlength(HASH_INFO_FUNCTION_NAME_SHA3384), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3384), strlength(HASH_INFO_COLUMN_TYPE_SHA3384), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3384), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3384), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3384), strlength(HASH_INFO_FUNCTION_VERSION_SHA3384), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3384), strlength(HASH_INFO_FUNCTION_DATE_SHA3384), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3384blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3384BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3384BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3384BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3384BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3384BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3384BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3384BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3384BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3384BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3384BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha3384mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3384MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA3384MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3384MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA3384MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3384MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3384MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3384MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA3384MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3384MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA3384MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3384macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3384MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3384MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3384MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3384MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3384MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3384MACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__SHA3512__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_sha3512)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3512), strlength(HASH_INFO_FUNCTION_NAME_SHA3512), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3512), strlength(HASH_INFO_COLUMN_TYPE_SHA3512), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3512), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3512), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3512), strlength(HASH_INFO_FUNCTION_VERSION_SHA3512), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3512), strlength(HASH_INFO_FUNCTION_DATE_SHA3512), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3512blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3512BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3512BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3512BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3512BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3512BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3512BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3512BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3512BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3512BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3512BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sha3512mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3512MAC), strlength(HASH_INFO_FUNCTION_NAME_SHA3512MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3512MAC), strlength(HASH_INFO_COLUMN_TYPE_SHA3512MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3512MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3512MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3512MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHA3512MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3512MAC), strlength(HASH_INFO_FUNCTION_DATE_SHA3512MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sha3512macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHA3512MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHA3512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHA3512MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHA3512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHA3512MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHA3512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHA3512MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHA3512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHA3512MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHA3512MACBLOB), free);
          break;
      }
      }
#endif

#endif

#if defined(__RIPEMD128__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_ripemd128)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD128), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD128), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD128), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD128), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD128), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD128), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD128), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD128), free);
          break;
      }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd128blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD128BLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD128BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD128BLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD128BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD128BLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD128BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD128BLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD128BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_ripemd128mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD128MAC), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD128MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD128MAC), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD128MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD128MAC), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD128MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD128MAC), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD128MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd128macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD128MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD128MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD128MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD128MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD128MACBLOB), free);
          break;
      }
      }
#endif
#endif


#if defined(__RIPEMD160__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_ripemd160)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD160), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD160), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD160), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD160), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD160), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD160), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD160), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD160), free);
        break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd160blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD160BLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD160BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD160BLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD160BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD160BLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD160BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD160BLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD160BLOB), free);
          break;
      }
      }
#endif

#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_ripemd160mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD160MAC), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD160MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD160MAC), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD160MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD160MAC), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD160MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD160MAC), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD160MAC), free);
          break;
      }
      }
#endif

#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd160macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD160MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD160MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD160MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD160MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD160MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD160MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD160MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD160MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD160MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__RIPEMD256__) || defined (__ALL__)
  else if( pCur->iRowid == hash_function_ripemd256)
  {
    switch( i ){
        case HASH_INFO_COLUMN_MODULE_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
        break;
        case HASH_INFO_COLUMN_FUNCTION_NAME:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD256), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD256), free);
        break;
        case HASH_INFO_COLUMN_TYPE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD256), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD256), free);
        break;
        case HASH_INFO_COLUMN_SIGNATURE:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256), free);
        break;
        case HASH_INFO_COLUMN_VERSION:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD256), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD256), free);
        break;
        case HASH_INFO_COLUMN_DATE_CREATED:
            sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD256), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD256), free);
        break;
    }
  }

#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd256blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD256BLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD256BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD256BLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD256BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD256BLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD256BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD256BLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD256BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_ripemd256mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD256MAC), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD256MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD256MAC), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD256MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD256MAC), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD256MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD256MAC), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD256MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd256macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD256MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD256MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD256MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD256MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD256MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__RIPEMD320__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_ripemd320)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD320), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD320), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD320), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD320), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD320), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD320), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD320), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD320), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd320blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD320BLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD320BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD320BLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD320BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD320BLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD320BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD320BLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD320BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_ripemd320mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD320MAC), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD320MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD320MAC), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD320MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD320MAC), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD320MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD320MAC), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD320MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_ripemd320macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_RIPEMD320MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_RIPEMD320MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_RIPEMD320MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_RIPEMD320MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_RIPEMD320MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_RIPEMD320MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_RIPEMD320MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_RIPEMD320MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_RIPEMD320MACBLOB), free);
          break;
      }
      }
#endif

#endif

#if defined(__BLAKE2B__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_blake2b)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2B), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2B), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2B), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2B), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2B), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2B), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2B), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2B), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2B), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2B), free);
          break;
          }
  }

#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_blake2bblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2BBLOB), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2BBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2BBLOB), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2BBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2BBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2BBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2BBLOB), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2BBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2BBLOB), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2BBLOB), free);
          break;
      }
      }
#endif

#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_blake2bmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2BMAC), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2BMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2BMAC), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2BMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2BMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2BMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2BMAC), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2BMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2BMAC), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2BMAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_blake2bmacblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2BMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2BMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2BMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2BMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2BMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2BMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2BMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2BMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2BMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2BMACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__BLAKE2S__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_blake2s)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2S), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2S), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2S), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2S), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2S), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2S), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2S), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2S), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2S), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2S), free);
          break;
          }
  }

#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_blake2sblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2SBLOB), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2SBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2SBLOB), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2SBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2SBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2SBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2SBLOB), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2SBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2SBLOB), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2SBLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_blake2smac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2SMAC), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2SMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2SMAC), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2SMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2SMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2SMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2SMAC), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2SMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2SMAC), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2SMAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_blake2smacblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_BLAKE2SMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_BLAKE2SMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_BLAKE2SMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_BLAKE2SMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_BLAKE2SMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_BLAKE2SMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_BLAKE2SMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_BLAKE2SMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_BLAKE2SMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_BLAKE2SMACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__TIGER__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_tiger)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_TIGER), strlength(HASH_INFO_FUNCTION_NAME_TIGER), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_TIGER), strlength(HASH_INFO_COLUMN_TYPE_TIGER), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_TIGER), strlength(HASH_INFO_COLUMN_SIGNATURE_TIGER), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_TIGER), strlength(HASH_INFO_FUNCTION_VERSION_TIGER), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_TIGER), strlength(HASH_INFO_FUNCTION_DATE_TIGER), free);
          break;
      }
      }
#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_tigerblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_TIGERBLOB), strlength(HASH_INFO_FUNCTION_NAME_TIGERBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_TIGERBLOB), strlength(HASH_INFO_COLUMN_TYPE_TIGERBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_TIGERBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_TIGERBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_TIGERBLOB), strlength(HASH_INFO_FUNCTION_VERSION_TIGERBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_TIGERBLOB), strlength(HASH_INFO_FUNCTION_DATE_TIGERBLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_tigermac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_TIGERMAC), strlength(HASH_INFO_FUNCTION_NAME_TIGERMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_TIGERMAC), strlength(HASH_INFO_COLUMN_TYPE_TIGERMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_TIGERMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_TIGERMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_TIGERMAC), strlength(HASH_INFO_FUNCTION_VERSION_TIGERMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_TIGERMAC), strlength(HASH_INFO_FUNCTION_DATE_TIGERMAC), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_tigermacblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_TIGERMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_TIGERMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_TIGERMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_TIGERMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_TIGERMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_TIGERMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_TIGERMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_TIGERMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_TIGERMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_TIGERMACBLOB), free);
          break;
      }
      }
#endif

#endif


#if defined(__SHAKE128__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_shake128)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE128), strlength(HASH_INFO_FUNCTION_NAME_SHAKE128), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE128), strlength(HASH_INFO_COLUMN_TYPE_SHAKE128), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE128), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE128), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE128), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE128), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE128), strlength(HASH_INFO_FUNCTION_DATE_SHAKE128), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_shake128blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE128BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHAKE128BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE128BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHAKE128BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE128BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE128BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE128BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE128BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE128BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHAKE128BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_shake128mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE128MAC), strlength(HASH_INFO_FUNCTION_NAME_SHAKE128MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE128MAC), strlength(HASH_INFO_COLUMN_TYPE_SHAKE128MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE128MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE128MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE128MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE128MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE128MAC), strlength(HASH_INFO_FUNCTION_DATE_SHAKE128MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) &&(__USE_MAC__)
  else if (pCur->iRowid == hash_function_shake128macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE128MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHAKE128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE128MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHAKE128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE128MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE128MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE128MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHAKE128MACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__SHAKE256__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_shake256)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE256), strlength(HASH_INFO_FUNCTION_NAME_SHAKE256), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE256), strlength(HASH_INFO_COLUMN_TYPE_SHAKE256), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE256), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE256), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE256), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE256), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE256), strlength(HASH_INFO_FUNCTION_DATE_SHAKE256), free);
          break;
      }
      }
#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_shake256blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE256BLOB), strlength(HASH_INFO_FUNCTION_NAME_SHAKE256BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE256BLOB), strlength(HASH_INFO_COLUMN_TYPE_SHAKE256BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE256BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE256BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE256BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE256BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE256BLOB), strlength(HASH_INFO_FUNCTION_DATE_SHAKE256BLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_shake256mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE256MAC), strlength(HASH_INFO_FUNCTION_NAME_SHAKE256MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE256MAC), strlength(HASH_INFO_COLUMN_TYPE_SHAKE256MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE256MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE256MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE256MAC), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE256MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE256MAC), strlength(HASH_INFO_FUNCTION_DATE_SHAKE256MAC), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_shake256macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SHAKE256MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SHAKE256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SHAKE256MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SHAKE256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SHAKE256MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SHAKE256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SHAKE256MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SHAKE256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SHAKE256MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SHAKE256MACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__SIPHASH64__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_siphash64)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH64), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH64), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH64), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH64), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH64), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH64), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH64), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH64), free);
          break;
      }
      }
#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_siphash64blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH64BLOB), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH64BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH64BLOB), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH64BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH64BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH64BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH64BLOB), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH64BLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_siphash64mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH64MAC), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH64MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH64MAC), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH64MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH64MAC), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH64MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH64MAC), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH64MAC), free);
          break;
      }
      }
#endif

#if  defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_siphash64macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH64MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH64MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH64MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH64MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH64MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH64MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH64MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH64MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH64MACBLOB), free);
          break;
      }
      }
#endif
#endif



#if defined(__SIPHASH128__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_siphash128)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH128), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH128), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH128), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH128), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH128), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH128), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH128), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH128), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_siphash128blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH128BLOB), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH128BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH128BLOB), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH128BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH128BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH128BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH128BLOB), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH128BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_siphash128mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH128MAC), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH128MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH128MAC), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH128MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH128MAC), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH128MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH128MAC), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH128MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_siphash128macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SIPHASH128MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SIPHASH128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SIPHASH128MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SIPHASH128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SIPHASH128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SIPHASH128MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SIPHASH128MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SIPHASH128MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SIPHASH128MACBLOB), free);
          break;
      }
      }
#endif
#endif


#if defined(__LSH224__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_lsh224)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH224), strlength(HASH_INFO_FUNCTION_NAME_LSH224), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH224), strlength(HASH_INFO_COLUMN_TYPE_LSH224), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH224), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH224), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH224), strlength(HASH_INFO_FUNCTION_VERSION_LSH224), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH224), strlength(HASH_INFO_FUNCTION_DATE_LSH224), free);
          break;
      }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh224blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH224BLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH224BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH224BLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH224BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH224BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH224BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH224BLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH224BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH224BLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH224BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_lsh224mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH224MAC), strlength(HASH_INFO_FUNCTION_NAME_LSH224MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH224MAC), strlength(HASH_INFO_COLUMN_TYPE_LSH224MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH224MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH224MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH224MAC), strlength(HASH_INFO_FUNCTION_VERSION_LSH224MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH224MAC), strlength(HASH_INFO_FUNCTION_DATE_LSH224MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh224macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH224MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH224MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH224MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH224MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH224MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH224MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH224MACBLOB), free);
          break;
      }
      }
#endif

#endif
#if defined(__LSH256__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_lsh256)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH256), strlength(HASH_INFO_FUNCTION_NAME_LSH256), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH256), strlength(HASH_INFO_COLUMN_TYPE_LSH256), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH256), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH256), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH256), strlength(HASH_INFO_FUNCTION_VERSION_LSH256), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH256), strlength(HASH_INFO_FUNCTION_DATE_LSH256), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh256blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH256BLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH256BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH256BLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH256BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH256BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH256BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH256BLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH256BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH256BLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH256BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_lsh256mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH256MAC), strlength(HASH_INFO_FUNCTION_NAME_LSH256MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH256MAC), strlength(HASH_INFO_COLUMN_TYPE_LSH256MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH256MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH256MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH256MAC), strlength(HASH_INFO_FUNCTION_VERSION_LSH256MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH256MAC), strlength(HASH_INFO_FUNCTION_DATE_LSH256MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh256macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH256MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH256MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH256MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH256MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH256MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH256MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH256MACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__LSH384__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_lsh384)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH384), strlength(HASH_INFO_FUNCTION_NAME_LSH384), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH384), strlength(HASH_INFO_COLUMN_TYPE_LSH384), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH384), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH384), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH384), strlength(HASH_INFO_FUNCTION_VERSION_LSH384), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH384), strlength(HASH_INFO_FUNCTION_DATE_LSH384), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh384blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH384BLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH384BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH384BLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH384BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH384BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH384BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH384BLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH384BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH384BLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH384BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_lsh384mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH384MAC), strlength(HASH_INFO_FUNCTION_NAME_LSH384MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH384MAC), strlength(HASH_INFO_COLUMN_TYPE_LSH384MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH384MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH384MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH384MAC), strlength(HASH_INFO_FUNCTION_VERSION_LSH384MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH384MAC), strlength(HASH_INFO_FUNCTION_DATE_LSH384MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh384macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH384MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH384MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH384MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH384MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH384MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH384MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH384MACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__LSH512__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_lsh512)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH512), strlength(HASH_INFO_FUNCTION_NAME_LSH512), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH512), strlength(HASH_INFO_COLUMN_TYPE_LSH512), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH512), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH512), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH512), strlength(HASH_INFO_FUNCTION_VERSION_LSH512), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH512), strlength(HASH_INFO_FUNCTION_DATE_LSH512), free);
          break;
      }
      }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh512blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH512BLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH512BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH512BLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH512BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH512BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH512BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH512BLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH512BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH512BLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH512BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_lsh512mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH512MAC), strlength(HASH_INFO_FUNCTION_NAME_LSH512MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH512MAC), strlength(HASH_INFO_COLUMN_TYPE_LSH512MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH512MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH512MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH512MAC), strlength(HASH_INFO_FUNCTION_VERSION_LSH512MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH512MAC), strlength(HASH_INFO_FUNCTION_DATE_LSH512MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_lsh512macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_LSH512MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_LSH512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_LSH512MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_LSH512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_LSH512MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_LSH512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_LSH512MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_LSH512MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_LSH512MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_LSH512MACBLOB), free);
          break;
      }
      }
#endif
#endif

#if defined(__SM3__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_sm3)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SM3), strlength(HASH_INFO_FUNCTION_NAME_SM3), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SM3), strlength(HASH_INFO_COLUMN_TYPE_SM3), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SM3), strlength(HASH_INFO_COLUMN_SIGNATURE_SM3), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SM3), strlength(HASH_INFO_FUNCTION_VERSION_SM3), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SM3), strlength(HASH_INFO_FUNCTION_DATE_SM3), free);
          break;
    }
  }
#if defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sm3blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SM3BLOB), strlength(HASH_INFO_FUNCTION_NAME_SM3BLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SM3BLOB), strlength(HASH_INFO_COLUMN_TYPE_SM3BLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SM3BLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SM3BLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SM3BLOB), strlength(HASH_INFO_FUNCTION_VERSION_SM3BLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SM3BLOB), strlength(HASH_INFO_FUNCTION_DATE_SM3BLOB), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_sm3mac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SM3MAC), strlength(HASH_INFO_FUNCTION_NAME_SM3MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SM3MAC), strlength(HASH_INFO_COLUMN_TYPE_SM3MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SM3MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_SM3MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SM3MAC), strlength(HASH_INFO_FUNCTION_VERSION_SM3MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SM3MAC), strlength(HASH_INFO_FUNCTION_DATE_SM3MAC), free);
          break;
      }
      }
#endif
#if defined(__USE_MAC__) && defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_sm3macblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_SM3MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_SM3MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_SM3MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_SM3MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_SM3MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_SM3MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_SM3MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_SM3MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_SM3MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_SM3MACBLOB), free);
          break;
      }
      }
#endif

#endif

#if defined(__WHIRLPOOL__) || defined (__ALL__)
  else if (pCur->iRowid == hash_function_whirlpool)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_WHIRLPOOL), strlength(HASH_INFO_FUNCTION_NAME_WHIRLPOOL), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_WHIRLPOOL), strlength(HASH_INFO_COLUMN_TYPE_WHIRLPOOL), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOL), strlength(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOL), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_WHIRLPOOL), strlength(HASH_INFO_FUNCTION_VERSION_WHIRLPOOL), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_WHIRLPOOL), strlength(HASH_INFO_FUNCTION_DATE_WHIRLPOOL), free);
          break;
    }
  }
#if  defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_whirlpoolblob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_WHIRLPOOLBLOB), strlength(HASH_INFO_FUNCTION_NAME_WHIRLPOOLBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_WHIRLPOOLBLOB), strlength(HASH_INFO_COLUMN_TYPE_WHIRLPOOLBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_WHIRLPOOLBLOB), strlength(HASH_INFO_FUNCTION_VERSION_WHIRLPOOLBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_WHIRLPOOLBLOB), strlength(HASH_INFO_FUNCTION_DATE_WHIRLPOOLBLOB), free);
          break;
      }
      }
#endif
#if  defined(__USE_MAC__)
      else if (pCur->iRowid == hash_function_whirlpoolmac)
      {
          switch (i) {
          case HASH_INFO_COLUMN_MODULE_NAME:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
              break;
          case HASH_INFO_COLUMN_FUNCTION_NAME:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_WHIRLPOOLMAC), strlength(HASH_INFO_FUNCTION_NAME_WHIRLPOOLMAC), free);
              break;
          case HASH_INFO_COLUMN_TYPE:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_WHIRLPOOLMAC), strlength(HASH_INFO_COLUMN_TYPE_WHIRLPOOLMAC), free);
              break;
          case HASH_INFO_COLUMN_SIGNATURE:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLMAC), free);
              break;
          case HASH_INFO_COLUMN_VERSION:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_WHIRLPOOLMAC), strlength(HASH_INFO_FUNCTION_VERSION_WHIRLPOOLMAC), free);
              break;
          case HASH_INFO_COLUMN_DATE_CREATED:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_WHIRLPOOLMAC), strlength(HASH_INFO_FUNCTION_DATE_WHIRLPOOLMAC), free);
              break;
          }
      }
#endif
#if  defined(__USE_MAC__) && defined(__USE_BLOB__)
      else if (pCur->iRowid == hash_function_whirlpoolmacblob)
      {
          switch (i) {
          case HASH_INFO_COLUMN_MODULE_NAME:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
              break;
          case HASH_INFO_COLUMN_FUNCTION_NAME:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_WHIRLPOOLMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_WHIRLPOOLMACBLOB), free);
              break;
          case HASH_INFO_COLUMN_TYPE:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_WHIRLPOOLMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_WHIRLPOOLMACBLOB), free);
              break;
          case HASH_INFO_COLUMN_SIGNATURE:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_WHIRLPOOLMACBLOB), free);
              break;
          case HASH_INFO_COLUMN_VERSION:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_WHIRLPOOLMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_WHIRLPOOLMACBLOB), free);
              break;
          case HASH_INFO_COLUMN_DATE_CREATED:
              sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_WHIRLPOOLMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_WHIRLPOOLMACBLOB), free);
              break;
          }
          }
#endif
#endif

#if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_cmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_CMACMAC), strlength(HASH_INFO_FUNCTION_NAME_CMACMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_CMACMAC), strlength(HASH_INFO_COLUMN_TYPE_CMACMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_CMACMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_CMACMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_CMACMAC), strlength(HASH_INFO_FUNCTION_VERSION_CMACMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_CMACMAC), strlength(HASH_INFO_FUNCTION_DATE_CMACMAC), free);
          break;
      }
      }
#endif
      #if (defined(__CMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_cmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_CMACMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_CMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_CMACMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_CMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_CMACMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_CMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_CMACMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_CMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_CMACMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_CMACMACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_cbcmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_CBCMACMAC), strlength(HASH_INFO_FUNCTION_NAME_CBCMACMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_CBCMACMAC), strlength(HASH_INFO_COLUMN_TYPE_CBCMACMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_CBCMACMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_CBCMACMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_CBCMACMAC), strlength(HASH_INFO_FUNCTION_VERSION_CBCMACMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_CBCMACMAC), strlength(HASH_INFO_FUNCTION_DATE_CBCMACMAC), free);
          break;
      }
      }
#endif
#if (defined(__CBCCMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_cbcmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_CBCMACMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_CBCMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_CBCMACMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_CBCMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_CBCMACMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_CBCMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_CBCMACMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_CBCMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_CBCMACMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_CBCMACMACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_dmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_DMACMAC), strlength(HASH_INFO_FUNCTION_NAME_DMACMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_DMACMAC), strlength(HASH_INFO_COLUMN_TYPE_DMACMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_DMACMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_DMACMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_DMACMAC), strlength(HASH_INFO_FUNCTION_VERSION_DMACMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_DMACMAC), strlength(HASH_INFO_FUNCTION_DATE_DMACMAC), free);
          break;
      }
      }
#endif
#if (defined(__DMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_dmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_DMACMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_DMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_DMACMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_DMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_DMACMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_DMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_DMACMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_DMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_DMACMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_DMACMACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_gmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_GMACMAC), strlength(HASH_INFO_FUNCTION_NAME_GMACMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_GMACMAC), strlength(HASH_INFO_COLUMN_TYPE_GMACMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_GMACMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_GMACMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_GMACMAC), strlength(HASH_INFO_FUNCTION_VERSION_GMACMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_GMACMAC), strlength(HASH_INFO_FUNCTION_DATE_GMACMAC), free);
          break;
      }
      }
#endif
#if (defined(__GMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_gmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_GMACMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_GMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_GMACMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_GMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_GMACMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_GMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_GMACMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_GMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_GMACMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_GMACMACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_hmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_HMACMAC), strlength(HASH_INFO_FUNCTION_NAME_HMACMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_HMACMAC), strlength(HASH_INFO_COLUMN_TYPE_HMACMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_HMACMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_HMACMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_HMACMAC), strlength(HASH_INFO_FUNCTION_VERSION_HMACMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_HMACMAC), strlength(HASH_INFO_FUNCTION_DATE_HMACMAC), free);
          break;
      }
      }
#endif
#if (defined(__HMAC__)||defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_hmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_HMACMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_HMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_HMACMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_HMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_HMACMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_HMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_HMACMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_HMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_HMACMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_HMACMACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_poly1305)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_POLY1305MAC), strlength(HASH_INFO_FUNCTION_NAME_POLY1305MAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_POLY1305MAC), strlength(HASH_INFO_COLUMN_TYPE_POLY1305MAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_POLY1305MAC), strlength(HASH_INFO_COLUMN_SIGNATURE_POLY1305MAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_POLY1305MAC), strlength(HASH_INFO_FUNCTION_VERSION_POLY1305MAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_POLY1305MAC), strlength(HASH_INFO_FUNCTION_DATE_POLY1305MAC), free);
          break;
      }
      }
#endif
#if (defined(__POLY1305__)|| defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_poly1305_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_POLY1305MACBLOB), strlength(HASH_INFO_FUNCTION_NAME_POLY1305MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_POLY1305MACBLOB), strlength(HASH_INFO_COLUMN_TYPE_POLY1305MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_POLY1305MACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_POLY1305MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_POLY1305MACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_POLY1305MACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_POLY1305MACBLOB), strlength(HASH_INFO_FUNCTION_DATE_POLY1305MACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_twotrackmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_TWOTRACKMAC), strlength(HASH_INFO_FUNCTION_NAME_TWOTRACKMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_TWOTRACKMAC), strlength(HASH_INFO_COLUMN_TYPE_TWOTRACKMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_TWOTRACKMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_TWOTRACKMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_TWOTRACKMAC), strlength(HASH_INFO_FUNCTION_VERSION_TWOTRACKMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_TWOTRACKMAC), strlength(HASH_INFO_FUNCTION_DATE_TWOTRACKMAC), free);
          break;
      }
      }
#endif
#if (defined(__TWOTRACK__)|| defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_twotrackmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_TWOTRACKMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_TWOTRACKMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_TWOTRACKMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_TWOTRACKMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_TWOTRACKMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_TWOTRACKMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_TWOTRACKMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_TWOTRACKMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_TWOTRACKMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_TWOTRACKMACBLOB), free);
          break;
      }
      }
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)
  else if (pCur->iRowid == hash_function_vmacmac)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_VMACMAC), strlength(HASH_INFO_FUNCTION_NAME_VMACMAC), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_VMACMAC), strlength(HASH_INFO_COLUMN_TYPE_VMACMAC), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_VMACMAC), strlength(HASH_INFO_COLUMN_SIGNATURE_VMACMAC), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_VMACMAC), strlength(HASH_INFO_FUNCTION_VERSION_VMACMAC), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_VMACMAC), strlength(HASH_INFO_FUNCTION_DATE_VMACMAC), free);
          break;
      }
      }
#endif
#if (defined(__VMAC__)|| defined(__ALL__)) && defined(__USE_MAC__)&&defined(__USE_BLOB__)
  else if (pCur->iRowid == hash_function_vmacmac_blob)
  {
      switch (i) {
      case HASH_INFO_COLUMN_MODULE_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_MODULE_NAME), strlength(HASH_INFO_MODULE_NAME), free);
          break;
      case HASH_INFO_COLUMN_FUNCTION_NAME:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_NAME_VMACMACBLOB), strlength(HASH_INFO_FUNCTION_NAME_VMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_TYPE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_TYPE_VMACMACBLOB), strlength(HASH_INFO_COLUMN_TYPE_VMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_SIGNATURE:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_COLUMN_SIGNATURE_VMACMACBLOB), strlength(HASH_INFO_COLUMN_SIGNATURE_VMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_VERSION:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_VERSION_VMACMACBLOB), strlength(HASH_INFO_FUNCTION_VERSION_VMACMACBLOB), free);
          break;
      case HASH_INFO_COLUMN_DATE_CREATED:
          sqlite3_result_text(ctx, strduplicate(HASH_INFO_FUNCTION_DATE_VMACMACBLOB), strlength(HASH_INFO_FUNCTION_DATE_VMACMACBLOB), free);
          break;
      }
      }
#endif
  else
  {
      char* buffer = sqlite3_mprintf("Invalid Cursor Position:[%lld] Max Row[%d]", pCur->iRowid, hash_function_hash_max);
    sqlite3_result_error(ctx, buffer, strlength(buffer));
    return SQLITE_ERROR;
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
    return (pCur->iRowid>= HASH_INFO_MAX);
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
    pIdxInfo->estimatedCost = (double)HASH_INFO_MAX;
    pIdxInfo->estimatedRows = HASH_INFO_MAX;
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
