Sqlite Hashing version 2024.04.27.1

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
  sqlitehashingext\ - these sources 
  

When built, load in sqlite with - files should be copied to the sqlite directory by the batch file

.load hashing
select * FROM hash_info; -- list hashes

select * FROM hash_sizes; -- list hash sizes

select md5(''); -- do md5 hash on empty string ['']

select sha256(''); -- do sha256 on empty string ['']

-- Note, this code attempts to operate on text and blob but assumes ability to load entire text or blob into memory at present ( no buffering )
