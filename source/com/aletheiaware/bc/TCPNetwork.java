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
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.bc.utils.ChannelUtils;
import com.aletheiaware.common.utils.CommonUtils;

import com.google.protobuf.ByteString;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class TCPNetwork implements Network {

    public static final int PORT_GET_BLOCK = 22222;
    public static final int PORT_GET_HEAD = 22322;
    public static final int PORT_BROADCAST = 23232;

    InetAddress[] peers;

    public TCPNetwork(InetAddress[] peers) {
        this.peers = peers;
    }

    @Override
    public Reference getHead(String channel) {
        for (InetAddress address : peers) {
            try (Socket s = new Socket(address, PORT_GET_HEAD)) {
                InputStream in = s.getInputStream();
                OutputStream out = s.getOutputStream();
                Reference.newBuilder()
                    .setChannelName(channel)
                    .build()
                    .writeDelimitedTo(out);
                out.flush();
                return Reference.parseDelimitedFrom(in);
            } catch (IOException e) {
                /* Ignored */
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public Block getBlock(Reference reference) {
        for (InetAddress address : peers) {
            try (Socket s = new Socket(address, PORT_GET_BLOCK)) {
                InputStream in = s.getInputStream();
                OutputStream out = s.getOutputStream();
                reference.writeDelimitedTo(out);
                out.flush();
                return Block.parseDelimitedFrom(in);
            } catch (IOException e) {
                /* Ignored */
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public void broadcast(Channel channel, Cache cache, ByteString hash, Block block) {
        for (InetAddress address : peers) {
            try (Socket s = new Socket(address, PORT_BROADCAST)) {
                InputStream in = s.getInputStream();
                OutputStream out = s.getOutputStream();
                for (;;) {
                    block.writeDelimitedTo(out);
                    out.flush();
                    Reference reference = Reference.parseDelimitedFrom(in);
                    ByteString remote = reference.getBlockHash();
                    if (remote.equals(hash)) {
                        // Broadcast accepted
                        System.out.println("Broadcast " + channel.getName() + " block " + new String(CommonUtils.encodeBase64URL(hash.toByteArray())) + " to " + address);
                        break;
                    } else {
                        // Broadcast rejected
                        Block referencedBlock = ChannelUtils.getBlock(channel.getName(), cache, this, remote);

                        if (referencedBlock.getLength() == block.getLength()) {
                            // Option A: remote points to a different chain of the same length, next chain to get a block mined on top wins
                            break;
                        } else if (referencedBlock.getLength() > block.getLength()) {
                            // Option B: remote points to a longer chain
                            throw new IllegalArgumentException(BC.ERROR_CHANNEL_OUT_OF_DATE);
                            // TODO re-mine all dropped records into new blocks on top of new head
                        } else {
                            // Option C: remote points to a shorter chain, and cannot update because the host is missing some blocks
                            block = referencedBlock;
                        }
                    }
                }
            } catch (IOException e) {
                /* Ignored */
                e.printStackTrace();
            }
        }
    }
}
