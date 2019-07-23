#!/bin/bash
#
# Copyright 2018 Aletheia Ware LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -x

if [ -d out ]; then
    rm -r out
fi
mkdir -p out/code
mkdir -p out/test

SOURCES=(
    source/com/aletheiaware/bc/BC.java
    source/com/aletheiaware/bc/Cache.java
    source/com/aletheiaware/bc/Channel.java
    source/com/aletheiaware/bc/Crypto.java
    source/com/aletheiaware/bc/FileCache.java
    source/com/aletheiaware/bc/MemoryCache.java
    source/com/aletheiaware/bc/Network.java
    source/com/aletheiaware/bc/Node.java
    source/com/aletheiaware/bc/PoWChannel.java
    source/com/aletheiaware/bc/TCPNetwork.java
    source/com/aletheiaware/bc/ThresholdChannel.java
    source/com/aletheiaware/bc/utils/BCUtils.java
    source/com/aletheiaware/bc/utils/ChannelUtils.java
)

PROTO_SOURCES=(
    source/com/aletheiaware/bc/BCProto.java
)

# Compile code
javac -cp libs/AletheiaWareCommonJava.jar:libs/protobuf-lite-3.0.1.jar ${SOURCES[*]} ${PROTO_SOURCES[*]} -d out/code
jar cvf out/BCJava.jar -C out/code .

TEST_SOURCES=(
    test/source/com/aletheiaware/bc/AllTests.java
    test/source/com/aletheiaware/bc/CryptoTest.java
    test/source/com/aletheiaware/bc/FileCacheTest.java
    test/source/com/aletheiaware/bc/MemoryCacheTest.java
    test/source/com/aletheiaware/bc/NodeTest.java
    test/source/com/aletheiaware/bc/PoWChannelTest.java
    test/source/com/aletheiaware/bc/TCPNetworkTest.java
    test/source/com/aletheiaware/bc/utils/BCUtilsTest.java
    test/source/com/aletheiaware/bc/utils/ChannelUtilsTest.java
)

# Compile tests
javac -cp libs/AletheiaWareCommonJava.jar:libs/protobuf-lite-3.0.1.jar:libs/junit-4.12.jar:libs/hamcrest-core-1.3.jar:libs/mockito-all-1.10.19.jar:out/BCJava.jar ${TEST_SOURCES[*]} -d out/test
jar cvf out/BCJavaTest.jar -C out/test .

# Run tests
java -cp libs/AletheiaWareCommonJava.jar:libs/protobuf-lite-3.0.1.jar:libs/junit-4.12.jar:libs/hamcrest-core-1.3.jar:libs/mockito-all-1.10.19.jar:out/BCJava.jar:out/BCJavaTest.jar org.junit.runner.JUnitCore com.aletheiaware.bc.AllTests

# Checkstyle
java -jar libs/checkstyle-8.11-all.jar -c ../checkstyle.xml ${SOURCES[*]} ${TEST_SOURCES[*]} > out/style || true
