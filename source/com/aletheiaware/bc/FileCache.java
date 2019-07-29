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
import com.aletheiaware.common.utils.CommonUtils;

import com.google.protobuf.ByteString;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class FileCache implements Cache {

    File directory;

    public FileCache(File directory) {
        this.directory = directory;
        new File(directory, "block").mkdirs();
        new File(directory, "channel").mkdirs();
    }

    @Override
    public Reference getHead(String channel) {
        File file = new File(new File(directory, "channel"), new String(CommonUtils.encodeBase64URL(channel.getBytes())));// Convert to Base64 for filesystem
        if (file.exists() && file.isFile()) {
            try (FileInputStream in = new FileInputStream(file)) {
                return Reference.parseFrom(in);
            } catch (IOException e) {
                /* Ignored */
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public Block getBlock(ByteString hash) {
        File file = new File(new File(directory, "block"), new String(CommonUtils.encodeBase64URL(hash.toByteArray())));// Convert to Base64 for filesystem
        if (file.exists() && file.isFile()) {
            try (FileInputStream in = new FileInputStream(file)) {
                return Block.parseFrom(in);
            } catch (IOException e) {
                /* Ignored */
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public List<BlockEntry> getBlockEntries(String channel, long timestamp) {
        File dir = new File(new File(directory, "entry"), new String(CommonUtils.encodeBase64URL(channel.getBytes())));// Convert to Base64 for filesystem
        List<BlockEntry> entries = new ArrayList<>();
        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                if (file.isFile()) {
                    Long t = Long.parseLong(file.getName());
                    if (t >= timestamp) {
                        try (FileInputStream in = new FileInputStream(file)) {
                            entries.add(BlockEntry.parseFrom(in));
                        } catch (IOException e) {
                            /* Ignored */
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        // TODO if size of entries is greater than max block size, start with oldest entries
        return entries;
    }

    @Override
    public Block getBlockContainingRecord(String channel, ByteString hash) {
        File mapping = new File(new File(directory, "mapping"), new String(CommonUtils.encodeBase64URL(channel.getBytes())));// Convert to Base64 for filesystem
        File file = new File(mapping, new String(CommonUtils.encodeBase64URL(hash.toByteArray())));// Convert to Base64 for filesystem
        if (file.exists() && file.isFile()) {
            try (FileInputStream in = new FileInputStream(file)) {
                return getBlock(ByteString.readFrom(in));
            } catch (IOException e) {
                /* Ignored */
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public void putHead(String channel, Reference reference) {
        File file = new File(new File(directory, "channel"), new String(CommonUtils.encodeBase64URL(channel.getBytes())));// Convert to Base64 for filesystem
        try (FileOutputStream out = new FileOutputStream(file)) {
            reference.writeTo(out);
            out.flush();
        } catch (IOException e) {
            /* Ignored */
            e.printStackTrace();
        }
    }

    @Override
    public void putBlock(ByteString hash, Block block) {
        File mapping = new File(new File(directory, "mapping"), new String(CommonUtils.encodeBase64URL(block.getChannelName().getBytes())));// Convert to Base64 for filesystem
        mapping.mkdirs();
        for (BlockEntry e : block.getEntryList()) {
            File file = new File(mapping, new String(CommonUtils.encodeBase64URL(e.getRecordHash().toByteArray())));// Convert to Base64 for filesystem
            try (FileOutputStream out = new FileOutputStream(file)) {
                hash.writeTo(out);
                out.flush();
            } catch (IOException ex) {
                /* Ignored */
                ex.printStackTrace();
            }
        }
        File file = new File(new File(directory, "block"), new String(CommonUtils.encodeBase64URL(hash.toByteArray())));// Convert to Base64 for filesystem
        try (FileOutputStream out = new FileOutputStream(file)) {
            block.writeTo(out);
            out.flush();
        } catch (IOException e) {
            /* Ignored */
            e.printStackTrace();
        }
    }

    @Override
    public void putBlockEntry(String channel, BlockEntry entry) {
        File dir = new File(new File(directory, "entry"), new String(CommonUtils.encodeBase64URL(channel.getBytes())));// Convert to Base64 for filesystem
        dir.mkdirs();
        File file = new File(dir, entry.getRecord().getTimestamp() + "");
        try (FileOutputStream out = new FileOutputStream(file)) {
            entry.writeTo(out);
            out.flush();
        } catch (IOException e) {
            /* Ignored */
            e.printStackTrace();
        }
    }

}