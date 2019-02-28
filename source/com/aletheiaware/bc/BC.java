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
import com.aletheiaware.bc.BCProto.KeyShare;
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.BCProto.SignatureAlgorithm;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.bc.utils.BCUtils.Pair;

import com.google.protobuf.ByteString;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class BC {

    public static class Channel {

        public interface EntryCallback {
            void onEntry(ByteString blockHash, Block block, BlockEntry entry);
        }

        public interface RecordCallback {
            void onRecord(ByteString blockHash, Block block, BlockEntry entry, byte[] key, byte[] payload);
        }

        public final String name;
        public final long threshold;
        public final File cache;
        public final InetAddress host;
        public ByteString headHash;
        public Block headBlock;

        public Channel(String name, long threshold, File cache, InetAddress host) {
            this.name = name;
            this.threshold = threshold;
            this.cache = cache;
            this.host = host;
            new File(cache, "block").mkdirs();
            new File(cache, "channel").mkdirs();
        }

        public void setHead(ByteString hash) {
            try {
                Block block = getBlock(hash);
                if (block != null) {
                    setHead(hash, block);
                }
            } catch (IOException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        private void setHead(ByteString hash, Block block) throws IOException, NoSuchAlgorithmException {
            // Check hash ones pass threshold
            long ones = BCUtils.getOnes(hash.toByteArray());
            if (ones < threshold) {
                System.err.println("Hash doesn't meet Proof-of-Work threshold: " + ones + " vs " + threshold);
                return;
            }
            // Check block length is longer than current
            if (headBlock != null && headBlock.getLength() >= block.getLength()) {
                System.err.println("Chain too short to replace head: " + block.getLength() + " vs " + headBlock.getLength());
                return;
            }
            String filename = new String(BCUtils.encodeBase64URL(name.getBytes()));// Convert to Base64 for filesystem
            File file = new File(new File(cache, "channel"), filename);
            FileOutputStream out = null;
            try {
                out = new FileOutputStream(file);
                Reference.newBuilder()
                        .setChannelName(name)
                        .setBlockHash(hash)
                        .build()
                        .writeTo(out);
                out.flush();
            } finally {
                if (out != null) {
                    out.close();
                }
            }
            headHash = hash;
            putBlock(block);
            headBlock = block;
        }

        public void sync() throws IOException, NoSuchAlgorithmException {
            // Update channel from remote host and download all blocks in chain node doesn't have
            Reference reference = getRemoteHead();
            if (reference != null) {
                ByteString head = reference.getBlockHash();
                if (head != null) {
                    Block block =  getBlock(head);
                    for (Block b = block; b != null;) {
                        ByteString hash = b.getPrevious();
                        if (hash == null || hash.isEmpty()) {
                            b = null;
                        } else {
                            b = getBlock(hash);
                        }
                    }
                    setHead(head, block);
                }
            }
        }

        public void cast() throws IOException {
            // Update remote host channel and upload all blocks in chain host doesn't have
            if (headHash == null || headBlock == null) {
                System.err.println("Nothing to cast");
                return;
            }
            Reference reference = BCUtils.setBlock(host, headBlock);
            if (reference == null) {
                System.err.println("Cast Unsuccessful");
                return;
            } else {
                ByteString remoteHeadHash = reference.getBlockHash();
                if (remoteHeadHash == null || remoteHeadHash.isEmpty()) {
                    System.err.println("Cast Unsuccessful Getting Remote Head Hash");
                    return;
                } else if (remoteHeadHash.equals(headHash)) {
                    System.out.println("Reference points to headBlock, cast successful!");
                    return;
                }
                /* TODO 
                int index = BCUtils.getChainIndex(headBlock, remoteHeadHash);
                if (index >= 0) {
                    System.err.println("Reference points to block in headBlockChain, cast unsuccessful, host is missing some blocks: cast each block after referenced one until headBlock");
                    return;
                } else {
                    */
                Block remoteHeadBlock = getBlock(remoteHeadHash);
                if (remoteHeadBlock == null) {
                    System.err.println("Cast Unsuccessful Getting Remote Head Block");
                    return;
                } else if (remoteHeadBlock.getLength() > headBlock.getLength()) {
                    System.err.println("Reference points to a longer chain, cast unsuccessful, host has a longer chain, find common link in chain and re-mine all dropped records into new blocks on top of new head");
                    return;
                } else {
                    System.err.println("Reference points to something else, cast unsuccessful, error");
                    return;
                }
            }
        }

        public void loadHead() throws IOException {
            String filename = new String(BCUtils.encodeBase64URL(name.getBytes()));// Convert to Base64 for filesystem
            File file = new File(new File(cache, "channel"), filename);
            FileInputStream in = null;
            if (file.exists()) {
                try {
                    in = new FileInputStream(file);
                    Reference r = Reference.parseFrom(in);
                    if (r != null && r.getChannelName().equals(name)) {
                        setHead(r.getBlockHash());
                    }
                } finally {
                    if (in != null) {
                        in.close();
                    }
                }
            }
        }

        public ByteString getHeadHash() {
            if (headHash == null || headHash.isEmpty()) {
                try {
                    loadHead();
                } catch (Exception e) {
                    /* Ignored */
                    e.printStackTrace();
                }
            }
            if (headHash == null || headHash.isEmpty()) {
                try {
                    Reference r = getRemoteHead();
                    if (r != null && r.getChannelName().equals(name)) {
                        setHead(r.getBlockHash());
                    }
                } catch (Exception e) {
                    /* Ignored */
                    e.printStackTrace();
                }
            }
            return headHash;
        }

        public Block getHeadBlock() {
            if (headBlock == null) {
                ByteString hash = getHeadHash();
                if (hash != null && !hash.isEmpty()) {
                    try {
                        Block b = getBlock(hash);
                        if (b != null) {
                            headBlock = b;
                        }
                    } catch (IOException e) {
                        /* Ignored */
                        e.printStackTrace();
                    }
                }
            }
            return headBlock;
        }

        public Block getBlock(ByteString blockHash) throws IOException {
            String filename = new String(BCUtils.encodeBase64URL(blockHash.toByteArray()));// Convert to Base64 for filesystem
            File file = new File(new File(cache, "block"), filename);
            FileInputStream in = null;
            Block b = null;
            if (file.exists()) {
                try {
                    in = new FileInputStream(file);
                    b = Block.parseFrom(in);
                } catch (IOException e) {
                    /* Ignored */
                    e.printStackTrace();
                } finally {
                    if (in != null) {
                        in.close();
                    }
                }
            }
            if (b == null) {
                b = getRemoteBlock(blockHash);
                try {
                    putBlock(b);
                } catch (Exception e) {
                    /* Ignored */
                    e.printStackTrace();
                }
            }
            return b;
        }

        public void putBlock(Block block) throws IOException, NoSuchAlgorithmException {
            if (block == null) {
                return;
            }
            byte[] hash = BCUtils.getHash(block.toByteArray());
            String filename = new String(BCUtils.encodeBase64URL(hash));// Convert to Base64 for filesystem
            File file = new File(new File(cache, "block"), filename);
            FileOutputStream out = null;
            try {
                out = new FileOutputStream(file);
                block.writeTo(out);
                out.flush();
            } finally {
                if (out != null) {
                    out.close();
                }
            }
        }

        public Reference getRemoteHead() throws IOException {
            return BCUtils.getHead(host, Reference.newBuilder()
                .setChannelName(name)
                .build());
        }

        public Block getRemoteBlock(ByteString blockHash) throws IOException {
            return getRemoteBlock(Reference.newBuilder()
                .setBlockHash(blockHash)
                .setChannelName(name)
                .build());
        }

        public Block getRemoteBlock(Reference reference) throws IOException {
            return BCUtils.getBlock(host, reference);
        }

        public void iterate(EntryCallback callback) throws IOException {
            ByteString hash = getHeadHash();
            while (hash != null && !hash.isEmpty()) {
                // System.out.println("BlockHash:" + new String(BCUtils.encodeBase64URL(hash.toByteArray())));
                Block block = getBlock(hash);
                for (BlockEntry e : block.getEntryList()) {
                    callback.onEntry(hash, block, e);
                }
                hash = block.getPrevious();
            }
        }

        public void read(String alias, KeyPair keys, byte[] recordHash, RecordCallback callback) throws IOException {
            iterate(new EntryCallback() {
                @Override
                public void onEntry(ByteString blockHash, Block block, BlockEntry entry) {
                    final ByteString rh = entry.getRecordHash();
                    // System.out.println("RecordHash:" + new String(BCUtils.encodeBase64URL(rh.toByteArray())));
                    if (recordHash == null || Arrays.equals(rh.toByteArray(), recordHash)) {
                        final Record record = entry.getRecord();
                        for (Record.Access a : record.getAccessList()) {
                            if (a.getAlias().equals(alias)) {
                                try {
                                    byte[] key = a.getSecretKey().toByteArray();
                                    byte[] decryptedKey = BCUtils.decryptRSA(keys.getPrivate(), key);
                                    byte[] decryptedPayload = BCUtils.decryptAES(decryptedKey, record.getPayload().toByteArray());
                                    callback.onRecord(blockHash, block, entry, key, decryptedPayload);
                                } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    public static class Node {

        public final String alias;
        public final KeyPair keys;

        public Node(String alias, KeyPair keys) {
            this.alias = alias;
            this.keys = keys;
        }

        public Reference mine(Channel channel, Map<String, PublicKey> acl, List<Reference> references, byte[] payload) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
            return mine(channel, BCUtils.createRecord(alias, keys, acl, references, payload));
        }

        public Reference mine(Channel channel, Record record) throws BadPaddingException, IOException, NoSuchAlgorithmException {
            ByteString recordHash = ByteString.copyFrom(BCUtils.getHash(record.toByteArray()));
            List<BlockEntry> entries = new ArrayList<>(1);
            entries.add(BlockEntry.newBuilder()
                    .setRecordHash(recordHash)
                    .setRecord(record)
                    .build());

            Pair<byte[], Block> result = mine(channel, entries);
            ByteString blockHash = ByteString.copyFrom(result.a);
            Block block = result.b;
            return Reference.newBuilder()
                    .setTimestamp(block.getTimestamp())
                    .setChannelName(channel.name)
                    .setBlockHash(blockHash)
                    .setRecordHash(recordHash)
                    .build();
        }

        public Pair<byte[], Block> mine(Channel channel, List<BlockEntry> entries) throws BadPaddingException, IOException, NoSuchAlgorithmException {
            Block.Builder bb = Block.newBuilder()
                    .setTimestamp(System.currentTimeMillis() * 1000000)// Convert milli to nano seconds
                    .setChannelName(channel.name)
                    .setLength(1)
                    .setMiner(alias)
                    .addAllEntry(entries);

            ByteString previousHash = channel.getHeadHash();
            Block previousBlock = channel.getHeadBlock();
            if (previousHash != null && previousBlock != null) {
                bb.setLength(previousBlock.getLength() + 1);
                bb.setPrevious(previousHash);
            }

            long size = bb.build().getSerializedSize();
            if (size > BCUtils.MAX_BLOCK_SIZE_BYTES) {
                System.err.println("Block too large: " + BCUtils.sizeToString(size) + " max: " + BCUtils.sizeToString(BCUtils.MAX_BLOCK_SIZE_BYTES));
                return null;
            }

            System.out.println("Mining " + channel.name + " " + size);

            long nonce = 0;
            long max = 0;
            for (; nonce >= 0; nonce++) {
                bb.setNonce(nonce);
                Block block = bb.build();
                byte[] data = block.toByteArray();
                byte[] hash = BCUtils.getHash(data);
                long ones = BCUtils.getOnes(hash);
                if (ones > max) {
                    System.out.println("Mining " + channel.name + " " + nonce + " " + ones + "/" + (hash.length * 8));
                    max = ones;
                }
                if (ones > channel.threshold) {
                    System.out.println("Mined " + channel.name + " " + BCUtils.timeToString(block.getTimestamp()) + " " + new String(BCUtils.encodeBase64URL(hash)));
                    channel.setHead(ByteString.copyFrom(hash), block);
                    channel.cast();
                    return new Pair(hash, block);
                }
            }
            return null;
        }
    }
}