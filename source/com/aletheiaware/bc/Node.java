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
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.Channel.BlockCallback;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.bc.utils.ChannelUtils;
import com.aletheiaware.common.utils.CommonUtils;
import com.aletheiaware.common.utils.CommonUtils.Pair;
import com.aletheiaware.crypto.Crypto;

import com.google.protobuf.ByteString;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Node {

    String alias;
    KeyPair key;
    Cache cache;
    Network network;
    Map<String, ThresholdChannel> channels = new HashMap<>();

    public Node(String alias, KeyPair key, Cache cache, Network network) {
        this.alias = alias;
        this.key = key;
        this.cache = cache;
        this.network = network;
    }

    public void addChannel(ThresholdChannel channel) {
        channels.put(channel.getName(), channel);
    }

    public ThresholdChannel getChannel(String name) {
        return channels.get(name);
    }

    public List<ThresholdChannel> getChannels() {
        TreeMap<String, ThresholdChannel> sorted = new TreeMap<>();
        sorted.putAll(channels);
        return new ArrayList<>(channels.values());
    }

    public Reference write(ThresholdChannel channel, Map<String, PublicKey> acl, List<Reference> references, byte[] payload) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        Record record = BCUtils.createRecord(alias, key, acl, references, payload);
        return ChannelUtils.writeRecord(channel.getName(), cache, record);
    }

    public long getLastMinedTimestamp(Channel channel) {
        long[] timestamp = {0L};
        // Iterate through the chain to find the most recent block mined by this node
        ChannelUtils.iterate(channel.getName(), channel.getHead(), null, cache, network, new BlockCallback() {
            @Override
            public boolean onBlock(ByteString hash, Block block) {
                if (alias.equals(block.getMiner())) {
                    timestamp[0] = block.getTimestamp();
                    return false;
                }
                return true;
            }
        });
        return timestamp[0];
    }

    public Pair<byte[], Block> mine(ThresholdChannel channel, MiningListener listener) throws IOException, NoSuchAlgorithmException {
        long timestamp = getLastMinedTimestamp(channel);

        List<BlockEntry> entries = cache.getBlockEntries(channel.getName(), timestamp);
    
        if (entries.isEmpty()) {
            throw new IllegalArgumentException(String.format(BC.ERROR_NO_ENTRIES_TO_MINE, channel.getName()));
        }

        // TODO check record signature of each entry

        Block.Builder bb = Block.newBuilder()
                .setTimestamp(System.currentTimeMillis() * 1000000)// Convert milli to nano seconds
                .setChannelName(channel.getName())
                .setLength(1)
                .setMiner(alias)
                .addAllEntry(entries);

        ByteString previousHash = channel.getHead();
        if (previousHash != null) {
            Block previousBlock = cache.getBlock(previousHash);
            if (previousBlock != null) {
                bb.setLength(previousBlock.getLength() + 1);
                bb.setPrevious(previousHash);
            }
        }

        long size = bb.build().getSerializedSize();
        if (size > BC.MAX_BLOCK_SIZE_BYTES) {
            throw new IllegalArgumentException(String.format(BC.ERROR_BLOCK_TOO_LARGE, CommonUtils.binarySizeToString(size), CommonUtils.binarySizeToString(BC.MAX_BLOCK_SIZE_BYTES)));
        }

        if (listener != null) {
            listener.onMiningStarted(channel, size);
        }

        long nonce = 0;
        long max = 0;
        for (; nonce >= 0; nonce++) {
            bb.setNonce(nonce);
            Block block = bb.build();
            byte[] hash = Crypto.getProtobufHash(block);
            long ones = BCUtils.getOnes(hash);
            if (ones > max) {
                if (listener != null) {
                    listener.onNewMaxOnes(channel, nonce, ones);
                }
                max = ones;
            }
            if (ones > channel.getThreshold()) {
                if (listener != null) {
                    listener.onMiningThresholdReached(channel, hash, block);
                }
                ChannelUtils.update(channel, cache, network, ByteString.copyFrom(hash), block);
                ChannelUtils.push(channel, cache, network);
                return new Pair(hash, block);
            }
        }
        throw new IllegalStateException(BC.ERROR_NONCE_WRAP_AROUND);
    }

    public interface MiningListener {

        void onMiningStarted(ThresholdChannel channel, long size);

        void onNewMaxOnes(ThresholdChannel channel, long nonce, long ones);

        void onMiningThresholdReached(ThresholdChannel channel, byte[] hash, Block block);
    }

}