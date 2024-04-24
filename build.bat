@echo off

REM this batch assumes a project path where sqlite is installed in a folder "sqlite" one folder up 
REM thie batch assumes a project path where cryptopp is installed in a folder "cryptopp" on folderup
REM make adjustments as necessary to find appropriate folders

set SQLITE_DIR=..\sqlite
set SQLITE=%SQLITE_DIR%\sqlite3.exe
set SQLITE_INC=%SQLITE_DIR%
set SQLITE_LIB=%SQLITE_DIR%
set CRYPTOPP_DIR=..\cryptopp
set CRYPTOPP_INC=%CRYPTOPP_DIR%
set CRYPTOPP_LIB=%CRYPTOPP_DIR%
set TEST_FUNCTIONS=test_functions.txt

set SQLITE_LIB_FILE=sqlite3.lib
set CRYPTOPP_LIB_FILE=cryptlib.lib

set HASHING_C=hashing.c
set CRYPTO_CPP=crypto.cpp

IF NOT EXIST %SQLITE% goto sqlite_ne
IF NOT EXIST %SQLITE_DIR% goto sqlite_dir_ne
IF NOT EXIST %SQLITE_INC% goto sqlite_inc_ne
IF NOT EXIST %SQLITE_LIB% goto sqlite_lib_ne
IF NOT EXIST %CRYPTOPP_DIR% goto cryptopp_dir_ne
IF NOT EXIST %CRYPTOPP_INC% goto cryptopp_inc_ne
IF NOT EXIST %CRYPTOPP_LIB% goto cryptopp_lib_ne
IF NOT EXIST %TEST_FUNCTIONS% goto test_funcs_ne

IF NOT EXIST %HASHING_C% goto hashing_file_ne
IF NOT EXIST %CRYPTO_CPP% goto crypto_file_ne
IF NOT EXIST %SQLITE_LIB%\%SQLITE_LIB_FILE% goto sqlite_lib_file_ne
IF NOT EXIST %CRYPTOPP_LIB%\%CRYPTOPP_LIB_FILE% goto crypto_lib_file_ne

cl hashing.c crypto.cpp  /EHsc -I %SQLITE_INC% -I %CRYPTOPP_INC% -link /MACHINE:X64 -LIBPATH:%SQLITE_LIB% -LIBPATH:%CRYPTOPP_LIB% sqlite3.lib cryptlib.lib kernel32.lib -dll -out:hashing.dll

REM "c:\Users\fliei\sources\repository\sqlite"
REM "c:\fliei\sources\repository\cryptopp"

if NOT "%ERRORLEVEL%"=="0" goto Failed
copy hashing.dll %SQLITE_DIR%
copy hashing.lib %SQLITE_DIR%
copy *.exp %SQLITE_DIR%
copy *.pdb %SQLITE_DIR%

echo .load hashing|..\sqlite\sqlite3.exe 
if NOT "%ERRORLEVEL%"=="0" goto Failed

echo .load hashing>test.sql
echo select hash_ping();>>test.sql
echo .quit>>test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo .load hashing>test.sql
echo select * FROM hash_info();>>test.sql
echo .quit>>test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

echo .load hashing>test.sql
echo select * FROM hash_sizes();>>test.sql
echo .quit>>test.sql

..\sqlite\sqlite3.exe < test.sql>result.log
type result.log

for /f %%A IN (test_functions.txt) do echo .load hashing>test%%A.sql && echo select %%A('')>>test%%A.sql && ..\sqlite\sqlite3.exe < test%%A.sql>result%%A.log && echo Testing %%A && type result%%A.log && del result%%A.log

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

:goto crypto_file_ne
echo source file: [%CRYPTO_CPP%] does not exist
exit /b 1

:sqlite_lib_file_ne
echo lib file: [%SQLITE_LIB%\%SQLITE_LIB_FILE%] does not exist
exit /b 1

:crypto_lib_file_ne
echo lib file: [%CRYPTOPP_LIB%\%CRYPTOPP_LIB_FILE%] does not exist
exit /b 1