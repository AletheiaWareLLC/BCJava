BCJava
======

This is a Java implementation of a blockchain using the BC data structures.

Setup
=====
Libraries

    mkdir libs
    ln -s <awcommonjavalib> libs/AletheiaWareCommonJava.jar
    ln -s <protolib> libs/protobuf-lite-3.0.1.jar

Protocol Buffers

    cd <path/to/BC>
    ./build.sh --javalite_out=<path/to/BCJava>/source/

Build
=====

    ./build.sh
