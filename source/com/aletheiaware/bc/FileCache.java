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
        String filename = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        File file = new File(new File(directory, "channel"), filename);
        if (file.exists()) {
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
        String filename = new String(BCUtils.encodeBase64URL(hash.toByteArray()));// Convert to Base64 for filesystem
        File file = new File(new File(directory, "block"), filename);
        if (file.exists()) {
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
        String filename = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        File dir = new File(new File(directory, "entry"), filename);
        List<BlockEntry> entries = new ArrayList<>();
        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
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
        // TODO if size of entries is greater than max block size, start with oldest entries
        return entries;
    }

    @Override
    public void putHead(String channel, Reference reference) {
        String filename = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        File file = new File(new File(directory, "channel"), filename);
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
        String filename = new String(BCUtils.encodeBase64URL(hash.toByteArray()));// Convert to Base64 for filesystem
        File file = new File(new File(directory, "block"), filename);
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
        String filename = new String(BCUtils.encodeBase64URL(channel.getBytes()));// Convert to Base64 for filesystem
        File dir = new File(new File(directory, "entry"), filename);
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