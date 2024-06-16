@echo off

REM this batch assumes a project path where sqlite is installed in a folder "sqlite" one folder up 
REM thie batch assumes a project path where cryptopp is installed in a folder "cryptopp" on folderup
REM make adjustments as necessary to find appropriate folders

set SQLITE_DIR=..\sqlite
set SQLITE=%SQLITE_DIR%\sqlite3.exe
set SQLITE_INC=%SQLITE_DIR%
set SQLITE_LIB=%SQLITE_DIR%
set CRYPTOPP_DIR=..\cryptopp\
set CRYPTOPP_INC=%CRYPTOPP_DIR%
set CRYPTOPP_LIB=%CRYPTOPP_DIR%x64\Output\Release
set TEST_FUNCTIONS=test_functions.txt

set SQLITE_LIB_FILE=sqlite3.lib
set CRYPTOPP_LIB_FILE=cryptlib.lib

set HASHING_C=hashing.c
set CRYPTO_HASHING_CPP=crypto_hashing.cpp
set CRYPTO_HASHING_BLOB_CPP=crypto_blob.cpp
set CRYPTO_MACCPP=crypto_mac.cpp

REM uncomment below to enable 
set CRYPTOPP=/D__CRYPTOCPP__
REM set DEFINE_USE_BLOB=/D__USE_BLOB__
set ENABLED_MD2=/D__MD2__
set ENABLED_MD4=/D__MD4__
set ENABLED_MD5=/D__MD5__
set ENABLED_SHA1=/D__SHA1__
set ENABLED_SHA224=/D__SHA224__
set ENABLED_SHA256=/D__SHA256__
set ENABLED_SHA384=/D__SHA384__
set ENABLED_SHA512=/D__SHA512__
set ENABLED_SHA3224=/D__SHA3224__
set ENABLED_SHA3256=/D__SHA3256__
set ENABLED_SHA3384=/D__SHA3384__
set ENABLED_SHA3512=/D__SHA3512__

set ENABLED_RIPEMD128=/D__RIPEMD128__
set ENABLED_RIPEMD160=/D__RIPEMD160__
set ENABLED_RIPEMD256=/D__RIPEMD256__
set ENABLED_RIPEMD320=/D__RIPEMD320__

set ENABLED_BLAKE2B=/D__BLAKE2B__
set ENABLED_BLAKE2S=/D__BLAKE2S__

set ENABLED_TIGER=/D__TIGER__




set UTIL_CPP=util.cpp

IF NOT EXIST %SQLITE% goto sqlite_ne
IF NOT EXIST %SQLITE_DIR% goto sqlite_dir_ne
IF NOT EXIST %SQLITE_INC% goto sqlite_inc_ne
IF NOT EXIST %SQLITE_LIB% goto sqlite_lib_ne
IF NOT EXIST %CRYPTOPP_DIR% goto cryptopp_dir_ne
IF NOT EXIST %CRYPTOPP_INC% goto cryptopp_inc_ne
IF NOT EXIST %CRYPTOPP_LIB% goto cryptopp_lib_ne
IF NOT EXIST %TEST_FUNCTIONS% goto test_funcs_ne

IF NOT EXIST %HASHING_C% goto hashing_file_ne
IF NOT EXIST %CRYPTO_HASHING_CPP% goto crypto_file_ne
IF NOT EXIST %CRYPTO_HASHING_BLOB_CPP% goto crypto_blob_file_ne
IF NOT EXIST %CRYPTO_MACCPP% goto crypto_macfile_ne
IF NOT EXIST %UTIL_CPP% goto util_cpp_ne
IF NOT EXIST %SQLITE_LIB%\%SQLITE_LIB_FILE% goto sqlite_lib_file_ne
IF NOT EXIST %CRYPTOPP_LIB%\%CRYPTOPP_LIB_FILE% goto crypto_lib_file_ne

echo cl -Zi /GS /RTC1 %HASHING_C% %CRYPTO_HASHING_CPP% %CRYPTO_HASHING_BLOB_CPP% %CRYPTO_MACCPP% %UTIL_CPP% /EHsc -I %SQLITE_INC% -I %CRYPTOPP_INC% %CRYPTOPP% %ENABLED_MD2% %ENABLED_MD4% %ENABLED_MD5% %ENABLED_SHA1% %ENABLED_SHA224% %ENABLED_SHA256% %ENABLED_SHA384% %ENABLED_SHA512% %ENABLED_SHA3224% %ENABLED_SHA3256% %ENABLED_SHA3384% %ENABLED_SHA3512% %ENABLED_RIPEMD128% %ENABLED_RIPEMD160% %ENABLED_RIPEMD256% %ENABLED_RIPEMD320% %ENABLED_BLAKE2B% %ENABLED_BLAKE2S% %ENABLED_TIGER% -link /MACHINE:X64 -LIBPATH:%SQLITE_LIB% -LIBPATH:%CRYPTOPP_LIB% sqlite3.lib cryptlib.lib kernel32.lib libcpmt.lib libcmt.lib libucrt.lib libvcruntime.lib -dll -out:hashing.dll
cl -Zi /GS /RTC1 %HASHING_C% %CRYPTO_HASHING_CPP% %CRYPTO_HASHING_BLOB_CPP% %CRYPTO_MACCPP% %UTIL_CPP% /EHsc -I %SQLITE_INC% -I %CRYPTOPP_INC% %CRYPTOPP% %ENABLED_MD2% %ENABLED_MD4% %ENABLED_MD5% %ENABLED_SHA1% %ENABLED_SHA224% %ENABLED_SHA256% %ENABLED_SHA384% %ENABLED_SHA512% %ENABLED_SHA3224% %ENABLED_SHA3256% %ENABLED_SHA3384% %ENABLED_SHA3512% %ENABLED_RIPEMD128% %ENABLED_RIPEMD160% %ENABLED_RIPEMD256% %ENABLED_RIPEMD320% %ENABLED_BLAKE2B% %ENABLED_BLAKE2S% %ENABLED_TIGER% -link /MACHINE:X64 -LIBPATH:%SQLITE_LIB% -LIBPATH:%CRYPTOPP_LIB% sqlite3.lib cryptlib.lib kernel32.lib libcpmt.lib libcmt.lib libucrt.lib libvcruntime.lib -dll -out:hashing.dll

REM "c:\Users\fliei\sources\repository\sqlite"
REM "c:\fliei\sources\repository\cryptopp"

if NOT "%ERRORLEVEL%"=="0" goto Failed
IF EXIST hashing.dll copy /y hashing.dll %SQLITE_DIR%
IF EXIST hashing.lib copy /y hashing.lib %SQLITE_DIR%
IF EXIST hashing.exp copy /y *.exp %SQLITE_DIR%
IF EXIST hashing.pdb copy /y *.pdb %SQLITE_DIR%

echo .load hashing|..\sqlite\sqlite3.exe 
if NOT "%ERRORLEVEL%"=="0" goto Failed

goto test_ping_exist
:after_test_ping_exist

goto test_hash_info_exist
:after_test_hash_info_exist

goto test_hash_sizes_exist
:after_test_hash_sizes_exist

goto test_md2_exist
:after_test_md2_exist

goto test_md4_exist
:after_test_md4_exist

goto test_md5_exist
:after_test_md5_exist

goto test_sha1_exist
:after_test_sha1_exist

goto test_sha224_exist
:after_test_sha224_exist

goto test_sha256_exist
:after_test_sha256_exist

goto test_sha384_exist
:after_test_sha384_exist

goto test_sha512_exist
:after_test_sha512_exist

goto test_sha3224_exist
:after_test_sha3224_exist

goto test_sha3256_exist
:after_test_sha3256_exist

goto test_sha3384_exist
:after_test_sha3384_exist

goto test_sha3512_exist
:after_test_sha3512_exist


goto test_ripemd128_exist
:after_test_ripemd128_exist

goto test_ripemd160_exist
:after_test_ripemd160_exist

goto test_ripemd256_exist
:after_test_ripemd256_exist

goto test_ripemd320_exist
:after_test_ripemd320_exist

goto test_blake2b_exist
:after_test_blake2b_exist

goto test_blake2s_exist
:after_test_blake2s_exist

goto test_tiger_exist
:after_test_tiger_exist


goto test_shake128_exist
:after_test_shake128_exist

goto test_shake256_exist
:after_test_shake256_exist

goto test_siphash64_exist
:after_test_siphash64_exist

goto test_siphash128_exist
:after_test_siphash128_exist

goto test_lsh224_exist
:after_test_lsh224_exist

goto test_lsh256_exist
:after_test_lsh256_exist

goto test_lsh384_exist
:after_test_lsh384_exist

goto test_lsh512_exist
:after_test_lsh512_exist

goto test_sm3_exist
:after_test_sm3_exist

goto test_whirlpool_exist
:after_test_whirlpool_exist

REM for /f %%A IN (test_functions.txt) do echo .load hashing>test%%A.sql && echo select %%A('')>>test%%A.sql && ..\sqlite\sqlite3.exe < test%%A.sql>result%%A.log && echo Testing %%A && type result%%A.log && del result%%A.log

goto Done

:Failed
echo Failed to build Done
exit /b 1

:Done
echo Done
exit /b 0

:sqlite_ne
echo Sqlite Executable [%SQLITE%] does not exist

:sqlite_dir_ne
echo Sqlite Directory [%SQLITE_DIR%] does not exist
exit /b 1

:sqlite_inc_ne
echo Sqlite Inc Directory [%SQLITE_INC%] does not exist
exit /b 1

:sqlite_lib_ne
echo Sqlite Lib Directory [%SQLITE_LIB%] does not exist
exit /b 1

:cryptopp_dir_ne
echo Crypto++ Directory [%CRYPTOPP_DIR%] does not exist
exit /b 1

:cryptopp_inc_ne
echo Crypto++ Inc Directory [%CRYPTOPP_INC%] does not exist
exit /b 1

:cryptopp_lib_ne
echo Crypto++ Lib Directory [%CRYPTOPP_LIB%] does not exist
exit /b 1

:test_funcs_ne
echo Test Functions file: [%FUNCTIONS%] does not exist
exit /b 1

:hashing_file_ne
echo source file: [%HASHING%] does not exist
exit /b 1

:crypto_file_ne
echo source file: [%CRYPTO_HASHING_CPP%] does not exist
exit /b 1

:crypto_blob_file_ne
echo source file: [%CRYPTO_HASHING_BLOB_CPP%] does not exist
exit /b 1

:crypto_macfile_ne
echo source file: [%CRYPTO_MACCPP%] does not exist
exit /b 1

:util_cpp_ne
echo source file: [%UTIL_CPP%] does not exist
exit /b 1


:sqlite_lib_file_ne
echo lib file: [%SQLITE_LIB%\%SQLITE_LIB_FILE%] does not exist
exit /b 1

:crypto_lib_file_ne
echo lib file: [%CRYPTOPP_LIB%\%CRYPTOPP_LIB_FILE%] does not exist
exit /b 1

:test_fail
echo Test Failed
exit /b 1

:test_ping_exist

echo Testing Ping Function Exists
echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='hash_ping';>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe < test.sql >result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="hash_ping" set HASH_PING_EXISTS=1
IF "%HASH_PING_EXISTS%"=="1" echo hash_ping exists
IF NOT "%HASH_PING_EXISTS%"=="1" goto test_fail

echo Testing Ping function
echo .load hashing>test.sql
echo select hash_ping();>>test.sql
echo .quit>>test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

goto after_test_ping_exist

:test_hash_info_exist

echo Testing hash_info Function Exists
echo .load hashing>test.sql
echo select * FROM pragma_module_list WHERE name='hash_info';>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe < test.sql >result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="hash_info" set HASH_INFO_EXISTS=1
IF "%HASH_INFO_EXISTS%"=="1" echo hash_info exists
IF NOT "%HASH_INFO_EXISTS%"=="1" goto test_fail


echo Testing hash_info function
echo .load hashing>test.sql
echo select * FROM hash_info();>>test.sql
echo .quit>>test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

goto after_test_hash_info_exist

:test_hash_sizes_exist

echo Testing hash_sizes Function Exists
echo .load hashing>test.sql
echo select * FROM pragma_module_list WHERE name='hash_sizes';>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe < test.sql >result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="hash_sizes" set HASH_SIZES_EXISTS=1
IF "%HASH_SIZES_EXISTS%"=="1" echo hash_sizes exists
IF NOT "%HASH_SIZES_EXISTS%"=="1" goto test_fail

echo Testing hash_sizes function
echo .load hashing>test.sql
echo select * FROM hash_sizes();>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

goto after_test_hash_sizes_exist

:test_md2_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='md2';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_MD2%"=="" goto after_test_md2_exist
echo Md2 Enabled - testing for md2 function
IF NOT "%ENABLED_MD2%"=="" echo "MD2 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="md2" set MD2_EXISTS=1
IF "%MD2_EXISTS%"=="1" echo md2 exists
IF NOT "%MD2_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select md2('''');';>>test.sql
echo select md2('');>>test.sql
echo select 'select md2(''a'');';>>test.sql
echo select md2('a');>>test.sql
echo select 'select md2(''this is a message'');';>>test.sql
echo select md2('this is a message');>>test.sql
echo select 'select md2(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select md2('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_md2_exist

:test_md4_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='md4';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_MD4%"=="" goto after_test_md4_exist
echo Md4 Enabled - testing for md4 function
IF NOT "%ENABLED_MD4%"=="" echo "MD4 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="md4" set MD4_EXISTS=1
IF "%MD4_EXISTS%"=="1" echo md4 exists
IF NOT "%MD4_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select md4('''');';>>test.sql
echo select md4('');>>test.sql
echo select 'select md4(''a'');';>>test.sql
echo select md4('a');>>test.sql
echo select 'select md4(''this is a message'');';>>test.sql
echo select md4('this is a message');>>test.sql
echo select 'select md4(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select md4('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_md4_exist
:test_md5_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='md5';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_MD5%"=="" goto after_test_md5_exist
echo Md5 Enabled - testing for md5 function
IF NOT "%ENABLED_MD5%"=="" echo "MD5 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="md5" set MD5_EXISTS=1
IF "%MD5_EXISTS%"=="1" echo md5 exists
IF NOT "%MD5_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select md5('''');';>>test.sql
echo select md5('');>>test.sql
echo select 'select md5(''a'');';>>test.sql
echo select md5('a');>>test.sql
echo select 'select md5(''this is a message'');';>>test.sql
echo select md5('this is a message');>>test.sql
echo select 'select md5(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select md5('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_md5_exist

:test_sha1_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha1';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA1%"=="" goto after_test_sha1_exist
echo Sha1 Enabled - testing for sha1 function
IF NOT "%ENABLED_SHA1%"=="" echo "SHA1 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha1" set SHA1_EXISTS=1
IF "%SHA1_EXISTS%"=="1" echo sha1 exists
IF NOT "%SHA1_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha1('''');';>>test.sql
echo select sha1('');>>test.sql
echo select 'select sha1(''a'');';>>test.sql
echo select sha1('a');>>test.sql
echo select 'select sha1(''this is a message'');';>>test.sql
echo select sha1('this is a message');>>test.sql
echo select 'select sha1(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha1('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha1_exist

:test_sha224_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha224';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA224%"=="" goto after_test_sha224_exist
echo Sha224 Enabled - testing for sha224 function
IF NOT "%ENABLED_SHA224%"=="" echo "SHA224 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha224" set SHA224_EXISTS=1
IF "%SHA224_EXISTS%"=="1" echo sha224 exists
IF NOT "%SHA224_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha224('''');';>>test.sql
echo select sha224('');>>test.sql
echo select 'select sha224(''a'');';>>test.sql
echo select sha224('a');>>test.sql
echo select 'select sha224(''this is a message'');';>>test.sql
echo select sha224('this is a message');>>test.sql
echo select 'select sha224(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha224('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha224_exist

:test_sha256_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha256';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA256%"=="" goto after_test_sha256_exist
echo Sha256 Enabled - testing for sha256 function
IF NOT "%ENABLED_SHA256%"=="" echo "SHA256 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha256" set SHA256_EXISTS=1
IF "%SHA256_EXISTS%"=="1" echo sha256 exists
IF NOT "%SHA256_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha256('''');';>>test.sql
echo select sha256('');>>test.sql
echo select 'select sha256(''a'');';>>test.sql
echo select sha256('a');>>test.sql
echo select 'select sha256(''this is a message'');';>>test.sql
echo select sha256('this is a message');>>test.sql
echo select 'select sha256(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha256('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha256_exist

:test_sha384_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha384';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA384%"=="" goto after_test_sha384_exist
echo Sha384 Enabled - testing for sha384 function
IF NOT "%ENABLED_SHA384%"=="" echo "SHA384 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha384" set SHA384_EXISTS=1
IF "%SHA384_EXISTS%"=="1" echo sha384 exists
IF NOT "%SHA384_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha384('''');';>>test.sql
echo select sha384('');>>test.sql
echo select 'select sha384(''a'');';>>test.sql
echo select sha384('a');>>test.sql
echo select 'select sha384(''this is a message'');';>>test.sql
echo select sha384('this is a message');>>test.sql
echo select 'select sha384(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha384('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha384_exist

:test_sha512_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha512';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA512%"=="" goto after_test_sha512_exist
echo Sha512 Enabled - testing for sha512 function
IF NOT "%ENABLED_SHA512%"=="" echo "SHA512 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha512" set SHA512_EXISTS=1
IF "%SHA512_EXISTS%"=="1" echo sha512 exists
IF NOT "%SHA512_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha512('''');';>>test.sql
echo select sha512('');>>test.sql
echo select 'select sha512(''a'');';>>test.sql
echo select sha512('a');>>test.sql
echo select 'select sha512(''this is a message'');';>>test.sql
echo select sha512('this is a message');>>test.sql
echo select 'select sha512(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha512('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log



goto after_test_sha512_exist


:test_sha3224_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha3224';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA3224%"=="" goto after_test_sha3224_exist
echo Sha3224 Enabled - testing for sha3224 function
IF NOT "%ENABLED_SHA3224%"=="" echo "SHA3224 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha3224" set SHA3224_EXISTS=1
IF "%SHA3224_EXISTS%"=="1" echo sha3224 exists
IF NOT "%SHA3224_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha3224('''');';>>test.sql
echo select sha3224('');>>test.sql
echo select 'select sha3224(''a'');';>>test.sql
echo select sha3224('a');>>test.sql
echo select 'select sha3224(''this is a message'');';>>test.sql
echo select sha3224('this is a message');>>test.sql
echo select 'select sha3224(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha3224('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha3224_exist

:test_sha3256_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha3256';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA3256%"=="" goto after_test_sha3256_exist
echo Sha3256 Enabled - testing for sha3256 function
IF NOT "%ENABLED_SHA3256%"=="" echo "SHA3256 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha3256" set SHA3256_EXISTS=1
IF "%SHA3256_EXISTS%"=="1" echo sha3256 exists
IF NOT "%SHA3256_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha3256('''');';>>test.sql
echo select sha3256('');>>test.sql
echo select 'select sha3256(''a'');';>>test.sql
echo select sha3256('a');>>test.sql
echo select 'select sha3256(''this is a message'');';>>test.sql
echo select sha3256('this is a message');>>test.sql
echo select 'select sha3256(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha3256('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha3256_exist

:test_sha3384_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha3384';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA3384%"=="" goto after_test_sha3384_exist
echo Sha3384 Enabled - testing for sha3384 function
IF NOT "%ENABLED_SHA3384%"=="" echo "SHA3384 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha3384" set SHA3384_EXISTS=1
IF "%SHA3384_EXISTS%"=="1" echo sha3384 exists
IF NOT "%SHA3384_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha3384('''');';>>test.sql
echo select sha3384('');>>test.sql
echo select 'select sha3384(''a'');';>>test.sql
echo select sha3384('a');>>test.sql
echo select 'select sha3384(''this is a message'');';>>test.sql
echo select sha3384('this is a message');>>test.sql
echo select 'select sha3384(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha3384('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_sha3384_exist

:test_sha3512_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='sha3512';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_SHA3512%"=="" goto after_test_sha3512_exist
echo Sha3512 Enabled - testing for sha3512 function
IF NOT "%ENABLED_SHA3512%"=="" echo "SHA3512 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="sha3512" set SHA3512_EXISTS=1
IF "%SHA3512_EXISTS%"=="1" echo sha3512 exists
IF NOT "%SHA3512_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select sha3512('''');';>>test.sql
echo select sha3512('');>>test.sql
echo select 'select sha3512(''a'');';>>test.sql
echo select sha3512('a');>>test.sql
echo select 'select sha3512(''this is a message'');';>>test.sql
echo select sha3512('this is a message');>>test.sql
echo select 'select sha3512(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select sha3512('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_sha3512_exist

:test_ripemd128_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='ripemd128';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_RIPEMD128%"=="" goto after_test_ripemd128_exist
echo RipeMD128 Enabled - testing for ripemd128 function
IF NOT "%ENABLED_RIPEMD128%"=="" echo "RIPEMD128 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="ripemd128" set RIPEMD128_EXISTS=1
IF "%RIPEMD128_EXISTS%"=="1" echo ripemd128 exists
IF NOT "%RIPEMD128_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select ripemd128('''');';>>test.sql
echo select ripemd128('');>>test.sql
echo select 'select ripemd128(''a'');';>>test.sql
echo select ripemd128('a');>>test.sql
echo select 'select ripemd128(''this is a message'');';>>test.sql
echo select ripemd128('this is a message');>>test.sql
echo select 'select ripemd128(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select ripemd128('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_ripemd128_exist

:test_ripemd160_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='ripemd160';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_RIPEMD160%"=="" goto after_test_ripemd160_exist
echo RipeMD160 Enabled - testing for ripemd160 function
IF NOT "%ENABLED_RIPEMD160%"=="" echo "RIPEMD160 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="ripemd160" set RIPEMD160_EXISTS=1
IF "%RIPEMD160_EXISTS%"=="1" echo ripemd160 exists
IF NOT "%RIPEMD160_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select ripemd160('''');';>>test.sql
echo select ripemd160('');>>test.sql
echo select 'select ripemd160(''a'');';>>test.sql
echo select ripemd160('a');>>test.sql
echo select 'select ripemd160(''this is a message'');';>>test.sql
echo select ripemd160('this is a message');>>test.sql
echo select 'select ripemd160(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select ripemd160('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_ripemd160_exist

:test_ripemd256_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='ripemd256';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_RIPEMD256%"=="" goto after_test_ripemd256_exist
echo RipeMD256 Enabled - testing for ripemd256 function
IF NOT "%ENABLED_RIPEMD256%"=="" echo "RIPEMD256 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="ripemd256" set RIPEMD256_EXISTS=1
IF "%RIPEMD256_EXISTS%"=="1" echo ripemd256 exists
IF NOT "%RIPEMD256_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select ripemd256('''');';>>test.sql
echo select ripemd256('');>>test.sql
echo select 'select ripemd256(''a'');';>>test.sql
echo select ripemd256('a');>>test.sql
echo select 'select ripemd256(''this is a message'');';>>test.sql
echo select ripemd256('this is a message');>>test.sql
echo select 'select ripemd256(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select ripemd256('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_ripemd256_exist

:test_ripemd320_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='ripemd320';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_RIPEMD320%"=="" goto after_test_ripemd320_exist
echo RipeMD320 Enabled - testing for ripemd320 function
IF NOT "%ENABLED_RIPEMD320%"=="" echo "RIPEMD320 Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="ripemd320" set RIPEMD320_EXISTS=1
IF "%RIPEMD320_EXISTS%"=="1" echo ripemd320 exists
IF NOT "%RIPEMD320_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select ripemd320('''');';>>test.sql
echo select ripemd320('');>>test.sql
echo select 'select ripemd320(''a'');';>>test.sql
echo select ripemd320('a');>>test.sql
echo select 'select ripemd320(''this is a message'');';>>test.sql
echo select ripemd320('this is a message');>>test.sql
echo select 'select ripemd320(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select ripemd320('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_ripemd320_exist

:test_blake2b_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='blake2b';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_BLAKE2B%"=="" goto after_test_blake2b_exist
echo Blake2B Enabled - testing for blake2b function
IF NOT "%ENABLED_BLAKE2B%"=="" echo "BLAKE2B Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="blake2b" set BLAKE2B_EXISTS=1
IF "%BLAKE2B_EXISTS%"=="1" echo blake2b exists
IF NOT "%BLAKE2B_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select blake2b('''');';>>test.sql
echo select blake2b('');>>test.sql
echo select 'select blake2b(''a'');';>>test.sql
echo select blake2b('a');>>test.sql
echo select 'select blake2b(''this is a message'');';>>test.sql
echo select blake2b('this is a message');>>test.sql
echo select 'select blake2b(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select blake2b('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log


goto after_test_blake2b_exist

:test_blake2s_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='blake2s';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_BLAKE2S%"=="" goto after_test_blake2s_exist
echo Blake2S Enabled - testing for blake2s function
IF NOT "%ENABLED_BLAKE2S%"=="" echo "BLAKE2S Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="blake2s" set BLAKE2S_EXISTS=1
IF "%BLAKE2S_EXISTS%"=="1" echo blake2s exists
IF NOT "%BLAKE2S_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select blake2s('''');';>>test.sql
echo select blake2s('');>>test.sql
echo select 'select blake2s(''a'');';>>test.sql
echo select blake2s('a');>>test.sql
echo select 'select blake2s(''this is a message'');';>>test.sql
echo select blake2s('this is a message');>>test.sql
echo select 'select blake2s(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select blake2s('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_blake2s_exist

:test_tiger_exist

echo .load hashing>test.sql
echo select * FROM pragma_function_list where name='tiger';>>test.sql
echo .quit>>test.sql
IF "%ENABLED_TIGER%"=="" goto after_test_tiger_exist
echo Tiger Enabled - testing for tiger function
IF NOT "%ENABLED_TIGER%"=="" echo "TIGER Set" && ..\sqlite\sqlite3.exe <test.sql>result.log
for /f "tokens=1 delims=|" %%A in (result.log) DO IF "%%A"=="tiger" set TIGER_EXISTS=1
IF "%TIGER_EXISTS%"=="1" echo tiger exists
IF NOT "%TIGER_EXISTS%"=="1" goto test_fail

echo .load hashing>test.sql
echo select 'select tiger('''');';>>test.sql
echo select tiger('');>>test.sql
echo select 'select tiger(''a'');';>>test.sql
echo select tiger('a');>>test.sql
echo select 'select tiger(''this is a message'');';>>test.sql
echo select tiger('this is a message');>>test.sql
echo select 'select tiger(''1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'');';>>test.sql
echo select tiger('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');>>test.sql
echo .quit>>test.sql
..\sqlite\sqlite3.exe <test.sql>result.log
type result.log

goto after_test_tiger_exist

:test_shake128_exist
goto after_test_shake128_exist

:test_shake256_exist
goto after_test_shake256_exist

:test_siphash64_exist
goto after_test_siphash64_exist

:test_siphash128_exist
goto after_test_siphash128_exist

:test_lsh224_exist
goto after_test_lsh224_exist

:test_lsh256_exist
goto after_test_lsh256_exist

:test_lsh384_exist
goto after_test_lsh384_exist

:test_lsh512_exist
goto after_test_lsh512_exist

:test_sm3_exist
goto after_test_sm3_exist

:test_whirlpool_exist
goto after_test_whirlpool_exist


echo Testing md2blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select md2blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo Testing md4blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select md4blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo Testing md5blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select md5blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo Testing sha1blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha1blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo Testing sha224blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha224blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo Testing sha256blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha256blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo Testing sha384blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha384blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log


echo Testing sha512blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha512blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log


echo Testing sha3224blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha3224blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log


echo Testing sha3256blob function
echo .load hashing>test.sql
echo create table test(test text,dateadded datetime);>>test.sql
echo insert into test(test,dateadded)VALUES('12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890','2024-06-12 00:00:00');>>test.sql
echo select sha3256blob('main','test','test',1);>>test.sql
echo .quit>>test.sql
type test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log



