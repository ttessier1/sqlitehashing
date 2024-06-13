cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project (hashing VERSION 2024.04.27 DESCRIPTION "Sqlite3 hashing extension")
include(CMakePrintHelpers)

if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW) 
endif()

 add_definitions(-DCRYPTOPP_ENABLE_NAMESPACE_WEAK=1)
 add_definitions(-D__ALL__=1)
 add_definitions(-D__USE_BLOB__=1)


 set(MSVC_RUNTIME "Static")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


#set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
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
hashing.c 
crypto_hashing.cpp
crypto_blob.cpp
crypto_mac.cpp 
util.cpp 
"encodings.c"
"encodings.h" 
"blob_hashing.h")

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

#get_cmake_property(_variableNames VARIABLES)
#list (SORT _variableNames)
#foreach (_variableName ${_variableNames})
#message(STATUS "${_variableName}=${${_variableName}}")
#endforeach()

add_custom_command(
  OUTPUT ../sqlite/hashing.dll
  COMMAND copy "${CMAKE_BUILD_TYPE}/hashing.lib" ${PROJECT_SOURCE_DIR}/../sqlite/hashing.dll
  COMMENT "Deploying the hashing.dll sqlite extension"
)
install(TARGETS hashing
        PUBLIC_HEADER
          DESTINATION ${PROJECT_SOURCE_DIR}/../sqlite/hashing.dll
)