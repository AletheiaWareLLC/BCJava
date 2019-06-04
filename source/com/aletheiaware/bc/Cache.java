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
import com.aletheiaware.bc.BCProto.Reference;

import com.google.protobuf.ByteString;

import java.util.List;

public interface Cache {

    Reference getHead(String channel);

    Block getBlock(ByteString hash);

    List<BlockEntry> getBlockEntries(String channel, long timestamp);

    void putHead(String channel, Reference reference);

    void putBlock(ByteString hash, Block block);

    void putBlockEntry(String channel, BlockEntry entry);
}
