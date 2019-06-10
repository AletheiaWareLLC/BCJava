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

package com.aletheiaware.bc.utils;

import com.aletheiaware.bc.BC;
import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.BlockEntry;
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.Cache;
import com.aletheiaware.bc.Channel;
import com.aletheiaware.bc.Channel.BlockCallback;
import com.aletheiaware.bc.Channel.KeyCallback;
import com.aletheiaware.bc.Channel.RecordCallback;
import com.aletheiaware.bc.Crypto;
import com.aletheiaware.bc.Network;

import com.google.protobuf.ByteString;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ChannelUtils {

    private ChannelUtils() {}

    public static void update(Channel channel, Cache cache, ByteString hash, Block block) throws NoSuchAlgorithmException {
        ByteString head = channel.getHead();
        if (head != null && head.equals(hash)) {
            // Channel up to date
            return;
        }

        // Check hash matches block hash
        byte[] h = Crypto.getProtobufHash(block);
        if (!Arrays.equals(hash.toByteArray(), h)) {
            throw new IllegalArgumentException(BC.ERROR_HASH_INCORRECT);
        }
        if (head != null && !head.isEmpty()) {
            Block b = cache.getBlock(head);
            // Check block chain is longer than current head
            if (b != null && b.getLength() >= block.getLength()) {
                throw new IllegalArgumentException(String.format(BC.ERROR_CHAIN_TOO_SHORT, block.getLength(), b.getLength()));
            }
        }

        channel.validate(cache, hash, block);

        channel.setTimestamp(block.getTimestamp());
        channel.setHead(hash);
        System.out.println(channel.getName() + " updated to " + BCUtils.timeToString(block.getTimestamp()) + " " + new String(BCUtils.encodeBase64URL(hash.toByteArray())));
        cache.putHead(channel.getName(), Reference.newBuilder()
                .setTimestamp(block.getTimestamp())
                .setChannelName(channel.getName())
                .setBlockHash(hash)
                .build());
        cache.putBlock(hash, block);
    }

    public static void readKey(ByteString hash, Block block, Cache cache, String alias, KeyPair key, ByteString recordHash, KeyCallback callback) throws IOException {
        iterate(hash, block, cache, new BlockCallback() {
            @Override
            public boolean onBlock(ByteString blockHash, Block block) {
                for (BlockEntry entry : block.getEntryList()) {
                    final ByteString rh = entry.getRecordHash();
                    // System.out.println("RecordHash:" + new String(BCUtils.encodeBase64URL(rh.toByteArray())));
                    if (rh.equals(recordHash)) {
                        final Record record = entry.getRecord();
                        if (record.getAccessCount() == 0) {
                            // No Access Declared - Data is public and unencrypted
                            if (!callback.onKey(blockHash, block, entry, null)) {
                                return false;
                            }
                        } else {
                            for (Record.Access a : record.getAccessList()) {
                                if (a.getAlias().equals(alias)) {
                                    try {
                                        byte[] k = a.getSecretKey().toByteArray();
                                        byte[] decryptedKey = Crypto.decryptRSA(key.getPrivate(), k);
                                        if (!callback.onKey(blockHash, block, entry, decryptedKey)) {
                                            return false;
                                        }
                                    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        }
                    }
                }
                return true;
            }
        });
    }

    public static void read(ByteString hash, Block block, Cache cache, String alias, KeyPair key, ByteString recordHash, RecordCallback callback) throws IOException {
        iterate(hash, block, cache, new BlockCallback() {
            @Override
            public boolean onBlock(ByteString blockHash, Block block) {
                for (BlockEntry entry : block.getEntryList()) {
                    final ByteString rh = entry.getRecordHash();
                    // System.out.println("RecordHash:" + new String(BCUtils.encodeBase64URL(rh.toByteArray())));
                    if (recordHash == null || rh.equals(recordHash)) {
                        final Record record = entry.getRecord();
                        if (record.getAccessCount() == 0) {
                            // No Access Declared - Data is public and unencrypted
                            if (!callback.onRecord(blockHash, block, entry, null, record.getPayload().toByteArray())) {
                                return false;
                            }
                        } else {
                            for (Record.Access a : record.getAccessList()) {
                                if (a.getAlias().equals(alias)) {
                                    try {
                                        byte[] k = a.getSecretKey().toByteArray();
                                        byte[] decryptedKey = Crypto.decryptRSA(key.getPrivate(), k);
                                        byte[] decryptedPayload = Crypto.decryptAES(decryptedKey, record.getPayload().toByteArray());
                                        if (!callback.onRecord(blockHash, block, entry, decryptedKey, decryptedPayload)) {
                                            return false;
                                        }
                                    } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        }
                    }
                }
                return true;
            }
        });
    }

    public static void iterate(ByteString hash, Block block, Cache cache, BlockCallback callback) {
        if (hash == null || hash.isEmpty()) {
            return;
        }
        Block b = block;
        if (b == null) {
            b = cache.getBlock(hash);
        }
        // Iterate throught each block in the chain
        while (b != null) {
            if (!callback.onBlock(hash, b)) {
                return;
            }
            hash = b.getPrevious();
            if (hash == null || hash.isEmpty()) {
                b = null;
            } else {
                b = cache.getBlock(hash);
            }
        }
    }

    public static void loadHead(Channel channel, Cache cache, Network network) {
        Reference reference = getHeadReference(channel.getName(), cache, network);
        if (reference != null) {
            channel.setTimestamp(reference.getTimestamp());
            channel.setHead(reference.getBlockHash());
        }
    }

    public static Reference getHeadReference(String channel, Cache cache, Network network) {
        Reference reference = cache.getHead(channel);
        if (reference == null && network != null) {
            reference = network.getHead(channel);
        }
        return reference;
    }

    public static Block getBlock(String channel, Cache cache, Network network, ByteString hash) {
        Block block = cache.getBlock(hash);
        if (block == null && network != null) {
            block = network.getBlock(Reference.newBuilder()
                    .setChannelName(channel)
                    .setBlockHash(hash)
                    .build());
            if (block != null) {
                cache.putBlock(hash, block);
            }
        }
        return block;
    }

    public static Reference writeRecord(String channel, Cache cache, Record record) throws NoSuchAlgorithmException {
        ByteString hash = ByteString.copyFrom(Crypto.getProtobufHash(record));
        cache.putBlockEntry(channel, BlockEntry.newBuilder()
                .setRecordHash(hash)
                .setRecord(record)
                .build());
        return Reference.newBuilder()
                .setTimestamp(record.getTimestamp())
                .setChannelName(channel)
                .setRecordHash(hash)
                .build();
    }

    public static void pull(Channel channel, Cache cache, Network network) throws NoSuchAlgorithmException {
        Reference reference = network.getHead(channel.getName());
        if (reference == null) {
            // Nothing to do
            return;
        }
        ByteString hash = reference.getBlockHash();
        if (hash.equals(channel.getHead())) {
            // Channel up-to-date
            return;
        }
        // Load head block
        Block block = getBlock(channel.getName(), cache, network, hash);
        // Ensure all previous blocks are loaded
        for (Block b = block; b != null;) {
            ByteString h = b.getPrevious();
            if (h != null && !h.isEmpty()) {
                b = getBlock(channel.getName(), cache, network, h);
            } else {
                b = null;
            }
        }
        update(channel, cache, hash, block);
    }

    public static void push(Channel channel, Cache cache, Network network) {
        ByteString hash = channel.getHead();
        Block block = cache.getBlock(hash);
        network.broadcast(channel, cache, hash, block);
    }
}
