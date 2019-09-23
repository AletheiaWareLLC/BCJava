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

    public static final long THRESHOLD_NONE = 0;
    public static final long THRESHOLD_EASIEST = 264; // 33/64
    public static final long THRESHOLD_EASY = 272; // 17/32
    public static final long THRESHOLD_STANDARD = 288; // 9/16
    public static final long THRESHOLD_HARD = 320; // 5/8
    public static final long THRESHOLD_HARDEST = 384; // 3/4

    public static final long THRESHOLD_PVB_HOUR = THRESHOLD_STANDARD;
    public static final long THRESHOLD_PVB_DAY = THRESHOLD_HARD;
    public static final long THRESHOLD_PVB_YEAR = THRESHOLD_HARDEST;

    public static final long MAX_BLOCK_SIZE_BYTES = 2L * 1024 * 1024 * 1024;// 2Gb
    public static final long MAX_PAYLOAD_SIZE_BYTES = 10L * 1024 * 1024;// 10Mb

    public static final String ERROR_CHANNEL_OUT_OF_DATE = "Channel out of date";
    public static final String ERROR_CHAIN_TOO_SHORT = "Chain too short to replace current head: %d vs %d";
    public static final String ERROR_HASH_INCORRECT = "Hash doesn't match block hash";
    public static final String ERROR_HASH_TOO_WEAK = "Hash doesn't meet Proof-of-Work threshold: %d vs %d";
    public static final String ERROR_PAYLOAD_TOO_LARGE = "Payload too large: %s max: %s";
    public static final String ERROR_BLOCK_TOO_LARGE = "Block too large: %s max: %s";
    public static final String ERROR_NONCE_WRAP_AROUND = "Nonce wrapped around before reaching threshold";
    public static final String ERROR_NO_ENTRIES_TO_MINE = "No entries to mine for channel: %s";

}