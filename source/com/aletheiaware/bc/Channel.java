/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aletheiaware.bc;

import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.BlockEntry;

import com.google.protobuf.ByteString;

public interface Channel {

    String getName();

    ByteString getHead();

    void setHead(ByteString hash);

    long getTimestamp();

    void setTimestamp(long timestamp);

    void validate(Cache cache, ByteString hash, Block block);

    public interface BlockCallback {
        boolean onBlock(ByteString blockHash, Block block);
    }

    public interface EntryCallback {
        boolean onEntry(ByteString blockHash, Block block, BlockEntry entry);
    }

    public interface KeyCallback {
        boolean onKey(ByteString blockHash, Block block, BlockEntry entry, byte[] key);
    }

    public interface RecordCallback {
        boolean onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload);
    }
}
