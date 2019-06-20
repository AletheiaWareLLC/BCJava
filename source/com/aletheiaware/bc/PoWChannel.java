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
import com.aletheiaware.bc.Channel.BlockCallback;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.bc.utils.ChannelUtils;

import com.google.protobuf.ByteString;

public class PoWChannel implements ThresholdChannel {

    public String name;
    public long threshold;
    public ByteString headHash;
    public long timestamp;

    public PoWChannel(String name, long threshold) {
        this.name = name;
        this.threshold = threshold;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public long getThreshold() {
        return threshold;
    }

    @Override
    public String toString() {
        return name + " " + threshold;
    }

    @Override
    public void validate(Cache cache, Network network, ByteString hash, Block block) {
        ChannelUtils.iterate(name, hash, block, cache, network, new BlockCallback() {
            @Override
            public boolean onBlock(ByteString blockHash, Block block) {
                // Check hash ones pass threshold
                int ones = BCUtils.getOnes(blockHash.toByteArray());
                if (ones < threshold) {
                    throw new IllegalArgumentException(String.format(BC.ERROR_HASH_TOO_WEAK, ones, threshold));
                }
                return true;
            }
        });
    }

    @Override
    public ByteString getHead() {
        return headHash;
    }

    @Override
    public void setHead(ByteString hash) {
        headHash = hash;
    }

    @Override
    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
