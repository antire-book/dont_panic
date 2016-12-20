# Don't Panic

This project combines a variety of Linux anti-reverse engineering techniques into one binary. The binary is a bind shell named *Trouble*. The bind shell requires a password. I've written all about the techniques used in a *free* book. You can find it on leanpub: https://leanpub.com/anti-reverse-engineering-linux

If you don't want to compile the project yourself then you can find it on VirusTotal:

https://www.virustotal.com/en/file/a39b83850757ca85a4ddd049226662ecf9f3644a29fb862ad27751b090a468b5/analysis/

## Dependencies
The code was written and tested on Ubuntu 16.04. I can't promise it works anywhere else. Furthermore, the project depends on:

1. musl
2. cmake

You can install the dependencies with the following command

```sh
sudo apt-get install cmake musl-dev musl-tools
```

## Compiling
To compile create a build directory, run cmake, and the type make. For example:

```sh
albino-lobster@ubuntu:~/dontpanic$ mkdir build
albino-lobster@ubuntu:~/dontpanic$ cd build/
albino-lobster@ubuntu:~/dontpanic/build$ cmake ..
-- The C compiler identification is GNU 5.4.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Detecting C compile features
-- Detecting C compile features - done
-- The CXX compiler identification is GNU 5.4.0
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Configuring done
-- Generating done
-- Build files have been written to: /home/albino-lobster/dontpanic/build
albino-lobster@ubuntu:~/dontpanic/build$ make
Scanning dependencies of target stripBinary
[  5%] Building CXX object stripBinary/CMakeFiles/stripBinary.dir/src/stripBinary.cpp.o
[ 11%] Linking CXX executable stripBinary
[ 11%] Built target stripBinary
Scanning dependencies of target fakeHeadersXBit
[ 16%] Building CXX object fakeHeadersXBit/CMakeFiles/fakeHeadersXBit.dir/src/fakeHeadersXBit.cpp.o
[ 22%] Linking CXX executable fakeHeadersXBit
[ 22%] Built target fakeHeadersXBit
Scanning dependencies of target encryptFunctions
[ 27%] Building CXX object encryptFunctions/CMakeFiles/encryptFunctions.dir/src/encryptFunctions.cpp.o
[ 33%] Building CXX object encryptFunctions/CMakeFiles/encryptFunctions.dir/src/rc4.c.o
[ 38%] Linking CXX executable encryptFunctions
[ 38%] Built target encryptFunctions
Scanning dependencies of target computeChecksums
[ 44%] Building CXX object computeChecksums/CMakeFiles/computeChecksums.dir/src/computeChecksums.cpp.o
[ 50%] Building CXX object computeChecksums/CMakeFiles/computeChecksums.dir/src/crc32.c.o
[ 55%] Linking CXX executable computeChecksums
[ 55%] Built target computeChecksums
Scanning dependencies of target madvise
[ 61%] Building CXX object madvise/CMakeFiles/madvise.dir/src/madvise.cpp.o
[ 66%] Linking CXX executable madvise
[ 66%] Built target madvise
Scanning dependencies of target cryptor
[ 72%] Building CXX object cryptor/CMakeFiles/cryptor.dir/src/cryptor.cpp.o
[ 77%] Linking CXX executable cryptor
[ 77%] Built target cryptor
Scanning dependencies of target addLDS
[ 77%] Built target addLDS
Scanning dependencies of target trouble
[ 83%] Building C object trouble/CMakeFiles/trouble.dir/src/trouble.c.o
[ 88%] Building C object trouble/CMakeFiles/trouble.dir/src/rc4.c.o
[ 94%] Building C object trouble/CMakeFiles/trouble.dir/src/crc32.c.o
[100%] Linking C executable trouble
The bind shell password is: wulg2FZo17WKoZ6e5Eyyet2BNBP1ppRE
1+0 records in
1+0 records out
1 byte copied, 7.5031e-05 s, 13.3 kB/s
[100%] Built target trouble
albino-lobster@ubuntu:~/dontpanic/build$ 
```

## Executing the program
Due to the use of ptrace, you'll neeed to execute with sudo. Otherwise, simply run the "trouble" binary like so:

```sh
albino-lobster@ubuntu:~/dontpanic/build$ sudo ./trouble/trouble 
[sudo] password for albino-lobster: 

```

This will cause the program to begin listening on port 1270.

## Connecting to the bind shell
You'll need the bind shell password in order to successfully connect. The password is output when you compile the program. In the output above the bind shell password is "wulg2FZo17WKoZ6e5Eyyet2BNBP1ppRE". Here is an example of connecting to the bindshell:

```sh
albino-lobster@ubuntu:~$ nc 127.0.0.1 1270
wulg2FZo17WKoZ6e5Eyyet2BNBP1ppRE
pwd
/home/albino-lobster/dontpanic/build
ls -l
total 60
-rw-rw-r-- 1 albino-lobster albino-lobster 13010 Dec 20 04:08 CMakeCache.txt
drwxrwxr-x 4 albino-lobster albino-lobster  4096 Dec 20 04:08 CMakeFiles
-rw-rw-r-- 1 albino-lobster albino-lobster  7418 Dec 20 04:08 Makefile
-rw-rw-r-- 1 albino-lobster albino-lobster  2050 Dec 20 04:08 cmake_install.cmake
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 computeChecksums
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 cryptor
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 encryptFunctions
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 fakeHeadersXBit
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 madvise
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 stripBinary
drwxrwxr-x 3 albino-lobster albino-lobster  4096 Dec 20 04:08 trouble
exit
albino-lobster@ubuntu:~$
```

## License
BSD-3-Clause
