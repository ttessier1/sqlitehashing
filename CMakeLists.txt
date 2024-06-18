cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project (hashing VERSION 2024.04.27 DESCRIPTION "Sqlite3 hashing extension")
include(CMakePrintHelpers)

if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW) 
endif()

 add_definitions(-DCRYPTOPP_ENABLE_NAMESPACE_WEAK=1)
 add_definitions(-D__ALL__=1)
 add_definitions(-D__MD2__=1)
 add_definitions(-D__MD4__=1)
 add_definitions(-D__MD5__=1)
 add_definitions(-D__SHA1__=1)
 add_definitions(-D__SHA224__=1)
 add_definitions(-D__SHA256__=1)
 add_definitions(-D__SHA284__=1)
 add_definitions(-D__SHA512__=1)
 add_definitions(-D__SHA3224__=1)
 add_definitions(-D__SHA3256__=1)
 add_definitions(-D__SHA3284__=1)
 add_definitions(-D__SHA3512__=1)
 add_definitions(-D__RIPEMD128__=1)
 add_definitions(-D__RIPEMD160__=1)
 add_definitions(-D__RIPEMD256__=1)
 add_definitions(-D__RIPEMD320__=1)

 add_definitions(-D__BLAKE2B__=1)
 add_definitions(-D__BLAKE2S__=1)

 add_definitions(-D__SHAKE128__=1)
 add_definitions(-D__SHAKE256__=1)

 add_definitions(-D__SIPHASH64__=1 )
 add_definitions(-D__SIPHASH128__=1 )

 add_definitions(-D__LSH224__=1 )
 add_definitions(-D__LSH256__=1 )
 add_definitions(-D__LSH384__=1 )
 add_definitions(-D__LSH512__=1 )

 add_definitions(-D__SM3__=1 )
 add_definitions(-D__WHIRLPOOL__=1 )

 add_definitions(-D__CMAC__=1 )
 add_definitions(-D__CBCMAC__=1 )
 add_definitions(-D__DMAC__=1 )
 add_definitions(-D__GMAC__=1 )
 add_definitions(-D__HMAC__=1 )
 add_definitions(-D__POLY1305__=1 )
 add_definitions(-D__TWOTRACK__=1 )
 add_definitions(-D__VMAC__=1 )

 add_definitions(-D__USE_BLOB__=1)
 add_definitions(-D__USE_MAC__=1)

 set(MSVC_RUNTIME "Static")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


set(CMAKE_CXX_STANDARD_LIBRARIES "kernel32.lib user32.lib")
set(CMAKE_C_FLAGS "-MT  /EHsc /source-charset:utf-8")
set(CMAKE_C_FLAGS_DEBUG "-MTd  /EHsc /source-charset:utf-8")
set(CMAKE_C_FLAGS_RELEASE "-MT  /EHsc /source-charset:utf-8")
set(CMAKE_CXX_FLAGS "-MT  /EHsc /source-charset:utf-8")
set(CMAKE_CXX_FLAGS_DEBUG "-MTd  /EHsc /source-charset:utf-8")
set(CMAKE_CXX_FLAGS_RELEASE "-MT  /EHsc /source-charset:utf-8")
message(OUTPUT_NAME="$<<CONFIG>_OUTPUT_NAME>")
message(BUILD_TYPE="${CMAKE_BUILD_TYPE}")
message(BUILD_TYPE_INIT="${CMAKE_BUILD_TYPE_INIT}")
message(PROJECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
message(CRYPTO_LIB="${PROJECT_SOURCE_DIR}/../cryptopp/x64/Output/${CMAKE_BUILD_TYPE}")
message(SQLITE3_LIB="${PROJECT_SOURCE_DIR}/../sqlite")
message(CMAKE_MSVC_RUNTIME_LIBRARY="${CMAKE_MSVC_RUNTIME_LIBRARY}")
message(MSVC_RUNTIME_LIBRARY="${MSVC_RUNTIME_LIBRARY}")

add_library(hashing 
SHARED
"hashing.c" 
"crypto_hashing.cpp"
"crypto_blob.cpp"
"crypto_mac.cpp" 
"crypto_mac_blob.cpp"
"util.cpp" 
"encodings.c"
"encodings.h" 
"blob_hashing.h"
"crypto_mac_blob.h"
)

link_directories(hashing 
	"${PROJECT_SOURCE_DIR}../sqlite"
	"${PROJECT_SOURCE_DIR}../cryptopp/x64/output/${CMAKE_BUILD_TYPE}"
)

include_directories(hashing 
	PRIVATE 
	${PROJECT_SOURCE_DIR}../sqlite
	${PROJECT_SOURCE_DIR}../cryptopp
)

#target_link_libraries(hashing sqlite3.lib)
find_library(CRYPTOPP_LIB cryptlib.lib HINTS "${PROJECT_SOURCE_DIR}/../cryptopp/x64/Output/${CMAKE_BUILD_TYPE}")

target_link_libraries(hashing PUBLIC "${CRYPTOPP_LIB}")

find_library(SQLITE3_LIB sqlite3.lib HINTS ${PROJECT_SOURCE_DIR}/../sqlite)
target_link_libraries(hashing PUBLIC "${SQLITE3_LIB}")

if(${CMAKE_BUILD_TYPE}=="Debug")
add_compile_definitions($<$<CONFIG:Debug>:_ITERATOR_DEBUG_LEVEL=2>)
elseif(${CMAKE_BUILD_TYPE}=="Release")
add_compile_definitions($<$<CONFIG:Release>:_ITERATOR_DEBUG_LEVEL=0>)
endif()


target_include_directories(hashing PUBLIC 
	../sqlite
	../cryptopp
)

add_custom_command(
  OUTPUT ../sqlite/hashing.dll
  COMMAND copy "${CMAKE_BUILD_TYPE}/hashing.lib" ${PROJECT_SOURCE_DIR}/../sqlite/hashing.dll
  COMMENT "Deploying the hashing.dll sqlite extension"
)
install(TARGETS hashing
        PUBLIC_HEADER
          DESTINATION ${PROJECT_SOURCE_DIR}/../sqlite/hashing.dll
)