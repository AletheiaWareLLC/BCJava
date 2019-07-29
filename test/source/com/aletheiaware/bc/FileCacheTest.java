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

import com.google.protobuf.ByteString;

import java.io.File;
import java.util.List;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class FileCacheTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    public File root;

    @Before
    public void setUp() throws Exception {
        root = folder.getRoot();
    }

    @Test
    public void testHead() throws Exception {
        FileCache cache = new FileCache(root);
        Assert.assertNull(cache.getHead("TEST"));
        ByteString hash = ByteString.copyFromUtf8("TEST_HASH");
        cache.putHead("TEST", Reference.newBuilder()
                .setTimestamp(1234)
                .setChannelName("TEST")
                .setBlockHash(hash)
                .build());
        Reference reference = cache.getHead("TEST");
        Assert.assertNotNull(reference);
        Assert.assertEquals(1234, reference.getTimestamp());
        Assert.assertEquals("TEST", reference.getChannelName());
        Assert.assertEquals(hash, reference.getBlockHash());
    }

    @Test
    public void testBlock() throws Exception {
        FileCache cache = new FileCache(root);
        Block block = Block.newBuilder()
                .setTimestamp(1234)
                .setChannelName("Test")
                .build();
        ByteString hash = ByteString.copyFrom(Crypto.getProtobufHash(block));
        Assert.assertNull(cache.getBlock(hash));
        cache.putBlock(hash, block);
        Assert.assertEquals(block, cache.getBlock(hash));
    }

    @Test
    public void testBlockEntry() throws Exception {
        FileCache cache = new FileCache(root);
        Record record1 = Record.newBuilder()
                .setTimestamp(1234)
                .build();
        ByteString hash1 = ByteString.copyFrom(Crypto.getProtobufHash(record1));
        Record record2 = Record.newBuilder()
                .setTimestamp(5678)
                .build();
        ByteString hash2 = ByteString.copyFrom(Crypto.getProtobufHash(record2));
        BlockEntry entry1 = BlockEntry.newBuilder()
                .setRecordHash(hash1)
                .setRecord(record1)
                .build();
        BlockEntry entry2 = BlockEntry.newBuilder()
                .setRecordHash(hash2)
                .setRecord(record2)
                .build();
        cache.putBlockEntry("TEST", entry1);
        cache.putBlockEntry("TEST", entry2);
        List<BlockEntry> entries = cache.getBlockEntries("TEST", 3456);
        Assert.assertEquals(1, entries.size());
        Assert.assertEquals(5678, entries.get(0).getRecord().getTimestamp());
    }

    @Test
    public void testBlockContainingRecord() throws Exception {
        FileCache cache = new FileCache(root);
        Record record = Record.newBuilder()
                .setTimestamp(1234)
                .build();
        ByteString recordHash = ByteString.copyFrom(Crypto.getProtobufHash(record));
        Block block = Block.newBuilder()
                .setTimestamp(1234)
                .setChannelName("Test")
                .addEntry(BlockEntry.newBuilder()
                    .setRecordHash(recordHash)
                    .setRecord(record))
                .build();
        ByteString hash = ByteString.copyFrom(Crypto.getProtobufHash(block));
        Assert.assertNull(cache.getBlockContainingRecord("Test", recordHash));
        cache.putBlock(hash, block);
        Assert.assertEquals(block, cache.getBlockContainingRecord("Test", recordHash));
    }
}