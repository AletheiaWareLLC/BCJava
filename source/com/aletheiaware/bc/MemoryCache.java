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
import com.aletheiaware.bc.utils.BCUtils;

import com.google.protobuf.ByteString;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MemoryCache implements Cache {

    Map<String, Block> blocks = new HashMap<>();
    Map<String, Reference> heads = new HashMap<>();
    Map<String, List<BlockEntry>> entries = new HashMap<>();

    @Override
    public Reference getHead(String channel) {
        String key = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        return heads.get(key);
    }

    @Override
    public Block getBlock(ByteString hash) {
        String key = new String(BCUtils.encodeBase64URL(hash.toByteArray()));// Convert to Base64 for filesystem
        return blocks.get(key);
    }

    @Override
    public List<BlockEntry> getBlockEntries(String channel, long timestamp) {
        String key = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        List<BlockEntry> es = entries.get(key);
        List<BlockEntry> results = new ArrayList<>();
        if (es != null) {
            for (BlockEntry e : es) {
                if (e.getRecord().getTimestamp() >= timestamp) {
                    results.add(e);
                }
            }
        }
        return results;
    }

    @Override
    public void putHead(String channel, Reference reference) {
        String key = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        heads.put(key, reference);
    }

    @Override
    public void putBlock(ByteString hash, Block block) {
        String key = new String(BCUtils.encodeBase64URL(hash.toByteArray()));// Convert to Base64 for filesystem
        blocks.put(key, block);
    }

    @Override
    public void putBlockEntry(String channel, BlockEntry entry) {
        String key = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        List<BlockEntry> es = entries.get(key);
        if (es == null) {
            es = new ArrayList<>();
            entries.put(key, es);
        }
        es.add(entry);
    }

}