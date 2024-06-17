Sqlite Hashing version 2024.06.15.1

#TODO: Bug Fix preprocessor macro inclusion -- priliminary completion
#TODO: Add blob specific functions for less memory intensive access to blobs or text objects
#TODO: Add test functions to batch build.bat file for base functions
#TODO: Add test functions to batch build.bat file for blob functions
#TODO: Add hash_info records for mac and blob functions
#TODO: Add hash_size records for mac and blob functions
TODO: Add blob specific functions for mac hashing algorithms
TODO: Add test functions to batch build.bat file for mac functions
TODO: Add test functions to batch build.bat file for mac and macblob functions
TODO: Verify mac functions adn macblob functions
TODO: Complete encryption functions
TODO: Add Compression
TODO: Add Base64Encoding
TODO: Add Base32Encoding
TODO: Add Base16Encoding
TODO: Add Base8Encoding

TODO: Add historical encryption algorithms
TODO: Add CMAKE
TODO: Make able to compile on other platforms/linux( Remove OutputDebugString in place of wrapper function )
TODO: Make error code returns to sqlite in case of errors

This project depends on 

sqlite3.exe and  sqlite3.lib https://sqlite.org/ (Version 3.45.3)

and 

cryptocpp https://www.cryptopp.com/ (Version 8.9)

This has been written on and for the Windows operating system, but it should be relatively easy to port to other platforms.

There is a build.bat batch file which assumes a lot and requires the use of the vcvars32.bat or vcvars64.bat to be used first to set up the build environment
Visual Studio 2022 was used to build.

The folderstructure for the  build.bat relies upon a folder structure similar to the following:

Project Folder\
  sqlite\ - sqlite.exe and sqlite.lib
  cryptopp\ - crypto++ header files and lib ( NOTE the lib file for this is copied to the extension directory )
    NOTE - in order to build crypto++ with md2 to md5 or other weak hashes, CRYPTOPP_ENABLE_NAMESPACE_WEAK must be defined
  sqlitehashingext\ - these sources 
  

When built, load in sqlite with - files should be copied to the sqlite directory by the batch file
the define __ALL__ should be used in order to get all available functions
in addition the __USE_BLOB__ define may be used to add blob specific function handling most of which are currently not implemented
in addition the individual algorithms may be activated without __ALL__ by using the indivual algorithms, for example: __MD5__, __SHA1__, __SHA256__
this may provide for a smaller overall binary and finer grain controll

.load hashing

select hash_ping(); -- confirm hashing loaded by function call

ping

select * FROM hash_info; -- list hashes

hashing|hash_info|table|select * FROM hash_info();|0.0.0.1|2024-01-19-01:01:01
hashing|hash_sizes|table|select * FROM hash_sizes();|0.0.0.1|2024-01-19-01:01:01
hashing|hash_ping|util|select hash_ping();|0.0.0.1|2024-01-19-01:01:01
hashing|rot13|transform|select rot([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|md2|hash|select md2([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|md2blob|hash|select md2blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macmd2|hash|select macmd2([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|md4|hash|select md4([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|md4blob|hash|select md4blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macmd4|hash|select macmd4([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|md5|hash|select md5([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|md5blob|hash|select md5blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macmd5|hash|select macmd5([stringtohash);|0.0.0.1|2024-06-10-01:01:01
hashing|sha1|hash|select sha1([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha1blob|hash|select sha1blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha1|hash|select macsha1([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha224|hash|select sha224([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha224blob|hash|select sha224blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha224|hash|select macsha224([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha256|hash|select sha256([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha256blob|hash|select sha256blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha256|hash|select macsha256([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha384|hash|select sha384([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha384blob|hash|select sha384blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha384|hash|select macsha384([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha512|hash|select sha512([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha512blob|hash|select sha512blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha512|hash|select macsha512([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha3224|hash|select sha3224([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha3224blob|hash|select sha3224blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha3224|hash|select macsha3224([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha3256|hash|select sha3256([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha3256blob|hash|select sha3256blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha3256|hash|select macsha3256([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha3384|hash|select sha3384([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha3384blob|hash|select sha3384blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha3384|hash|select macsha3384([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sha3512|hash|select sha3512([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sha3512blob|hash|select sha3512blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsha3512|hash|select macsha3512([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|ripemd128|hash|select ripemd128([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|ripemd128blob|hash|select ripemd128blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macripemd128|hash|select macripemd128([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|ripemd160|hash|select ripemd160([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|ripemd160blob|hash|select ripemd160blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macripemd160|hash|select macripemd160();|0.0.0.1|2024-06-10-01:01:01
hashing|ripemd256|hash|select ripemd256([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|ripemd256blob|hash|select ripemd256blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macripemd256|hash|select macripemd256([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|ripemd320|hash|select ripemd320([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|ripemd320blob|hash|select ripemd320blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macripemd320|hash|select macripemd320([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|blake2b|hash|select blake2b([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|blake2bblob|hash|select blake2bblob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macblake2b|hash|select macblake2b([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|blake2s|hash|select blake2s([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|blake2sblob|hash|select blake2sblob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macblake2s|hash|select macblake2s([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|tiger|hash|select tiger([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|tigerblob|hash|select tigerblob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|mactiger|hash|select mactiger([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|shake128|hash|select shake128([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|shake128blob|hash|select shake128blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macshake128|hash|select macshake128([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|shake256|hash|select shake256([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|shake256blob|hash|select shake256blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macshake256|hash|select macshake256([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|siphash64|hash|select siphash64([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|siphash64blob|hash|select siphash64blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsiphash64|hash|select macsiphash64([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|siphash128|hash|select siphash128([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|siphash128blob|hash|select siphash128blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsiphash128|hash|select macsiphash128([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|lsh224|hash|select lsh224([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|lsh224blob|hash|select lsh224blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|maclsh224|hash|select maclsh224([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|lsh256|hash|select lsh256([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|lsh256blob|hash|select lsh256blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|maclsh256|hash|select maclsh256([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|lsh384|hash|select lsh384([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|lsh384blob|hash|select lsh384blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|lsh384MAC|hash|select lsh384MAC([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|lsh512|hash|select lsh512([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|lsh512blob|hash|select lsh512blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|maclsh512|hash|select maclsh512([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|sm3|hash|select sm3([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|sm3blob|hash|select sm3blob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macsm3|hash|select macsm3([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|whirlpool|hash|select whirlpool([stringtohash]);|0.0.0.1|2024-01-19-01:01:01
hashing|whirlpoolblob|hash|select whirlpoolblob([database],[table],[column],[rowid]);|0.0.0.1|2024-06-10-01:01:01
hashing|macwhirlpool|hash|select macwhirlpool([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|maccmac|hash|select maccmac([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|maccbcmac|hash|select maccbcmac([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|macdmac|hash|select macdmac([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|macgmac|hash|select macgmac([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|machmac|hash|select machmac([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|macpoly1305|hash|select macpoly1305([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|mactwotrack|hash|select mactwotrack([stringtohash]);|0.0.0.1|2024-06-10-01:01:01
hashing|macvmac|hash|select macvmac([stringtohash]);|0.0.0.1|2024-06-10-01:01:01

select * FROM hash_sizes; -- list hash sizes

hashing|md2|16
hashing|md2blob|16
hashing|macmd2|16
hashing|md4|16
hashing|md4blob|16
hashing|macmd4|16
hashing|md5|16
hashing|md5blob|16
hashing|macmd5|16
hashing|sha1|20
hashing|sha1blob|20
hashing|macsha1|20
hashing|sha224|28
hashing|sha224blob|28
hashing|macsha224|28
hashing|sha256|28
hashing|sha256blob|28
hashing|macsha256|28
hashing|sha384|32
hashing|sha384blob|32
hashing|macsha384|32
hashing|sha512|48
hashing|sha512blob|48
hashing|macsha512|48
hashing|sha3224|28
hashing|sha3224blob|28
hashing|macsha3224|28
hashing|sha3256|0
hashing|sha3256blob|0
hashing|macsha3256|0
hashing|sha3384|48
hashing|sha3384blob|48
hashing|macsha3384|48
hashing|sha3512|64
hashing|sha3512blob|64
hashing|macsha3512|64
hashing|ripemd128|16
hashing|ripemd128blob|16
hashing|macripemd128|16
hashing|ripenmd160|20
hashing|ripenmd160blob|20
hashing|macripenmd160|20
hashing|ripemd256|32
hashing|ripemd256blob|32
hashing|macripemd256|32
hashing|ripemd320|40
hashing|ripemd320blob|40
hashing|macripemd320|40
hashing|blake2b|0
hashing|blake2bblob|0
hashing|macblake2b|0
hashing|blake2s|32
hashing|blake2sblob|32
hashing|macblake2s|32
hashing|tiger|24
hashing|tigerblob|24
hashing|mactiger|24
hashing|shake128|32
hashing|shake128blob|32
hashing|macshake128|32
hashing|shake256|64
hashing|shake256blob|64
hashing|shake256blob|64
hashing|siphash64|64
hashing|siphash64blob|64
hashing|macsiphash64|64
hashing|siphash128|64
hashing|siphash128blob|64
hashing|macsiphash128|64
hashing|lsh224|8
hashing|lsh224blob|8
hashing|maclsh224|8
hashing|lsh256|8
hashing|lsh256blob|8
hashing|maclsh256|8
hashing|lsh384|8
hashing|lsh384blob|8
hashing|maclsh384|8
hashing|lsh512|8
hashing|lsh512blob|8
hashing|maclsh512|8
hashing|sm3|8
hashing|sm3blob|8
hashing|macsm3|8
hashing|whirlpool|8
hashing|whirlpoolblob|8
hashing|macwhirlpool|8
hashing|maccmac|8
hashing|maccbcmac|8
hashing|macdmac|8
hashing|macgmac|8
hashing|machmac|8
hashing|macpoly1305|8
hashing|mactwotrack|8
hashing|macvmac|8

select md5(''); -- do md5 hash on empty string ['']

D41D8CD98F00B204E9800998ECF8427E

select tohex('test');

74657374

select fromhex('74657374');

test

select sha256(''); -- do sha256 on empty string ['']

E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855

-- Note, this code attempts to operate on text and blob but assumes ability to load entire text or blob into memory at present ( no buffering )
