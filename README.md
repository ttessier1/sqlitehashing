Sqlite Hashing version 2024.04.27.1

TODO: Verify mac functions
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

.load hashing

select hash_ping(); -- confirm hashing loaded by function call

ping

select * FROM hash_info; -- list hashes

hashing|hash_info|table|select * FROM hash_info();
hashing|hash_size|table|select * FROM hash_sizes();
hashing|hash_ping|util|select hash_ping();
hashing|rot13|transform|select rot('');
hashing|md2|hash|select md2('');
hashing|md4|hash|select md4('');
hashing|md5|hash|select md5('');
hashing|sha1|hash|select md2('');
hashing|sha224|hash|select md2('');
hashing|sha256|hash|select sha256('');
hashing|sha384|hash|select sha384('');
hashing|sha512|hash|select sha512('');
hashing|sha3-224|hash|select sha3224('');
hashing|sha3-256|hash|select sha3256('');
hashing|sha3-384|hash|select sha3384('');
hashing|sha3-512|hash|select sha3512('');
hashing|ripemd-128|hash|select ripemd128('');
hashing|ripemd-160|hash|select ripemd160('');
hashing|ripemd-256|hash|select ripemd256('');
hashing|ripemd-320|hash|select ripemd320('');
hashing|blake2b|hash|select blake2b('');
hashing|blake2s|hash|select blake2s('');
hashing|tiger|hash|select shake128('');
hashing|shake128|hash|
hashing|shake256|hash|select shake256('');
hashing|siphash64|hash|select siphash64('');
hashing|siphash128|hash|select siphash128('');
hashing|lsh224|hash|select lsh224('');
hashing|lsh256|hash|select lsh256('');
hashing|lsh384|hash|select lsh384('');
hashing|lsh512|hash|select lsh512('');
hashing|sm3|hash|select sm3('');
hashing|whirlpool|hash|select whirlpool('');

select * FROM hash_sizes; -- list hash sizes

hashing|md2|16|
hashing|md4|16|
hashing|md5|16|
hashing|sha1|20|
hashing|sha224|28|
hashing|sha256|32|
hashing|sha384|48|
hashing|sha512|64|
hashing|sha3-224|28|
hashing|sha3-256|32|
hashing|sha3-384|48|
hashing|sha3-512|64|
hashing|ripemd-128|16|
hashing|ripenmd-160|20|
hashing|ripemd-256|32|
hashing|ripemd-320|40|
hashing|blake2b|64|
hashing|blake2s|32|
hashing|tiger|24|
hashing|shake-128|32|
hashing|shake-256|64|
hashing|sip-hash64|8|
hashing|sip-hash128|16|
hashing|lsh-224|28|
hashing|lsh-256|32|
hashing|lsh-384|48|
hashing|lsh-512|64|
hashing|sm3|32|
hashing|whirlpool|64|

select md5(''); -- do md5 hash on empty string ['']

D41D8CD98F00B204E9800998ECF8427E

select tohex('test');

74657374

select fromhex('74657374');

test

select sha256(''); -- do sha256 on empty string ['']

E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855

-- Note, this code attempts to operate on text and blob but assumes ability to load entire text or blob into memory at present ( no buffering )
