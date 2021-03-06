/*
 * Copyright 2018 Aletheia Ware LLC
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
import com.aletheiaware.bc.Channel.EntryCallback;
import com.aletheiaware.common.utils.CommonUtils;
import com.aletheiaware.crypto.Crypto;
import com.aletheiaware.crypto.CryptoProto.EncryptionAlgorithm;
import com.aletheiaware.crypto.CryptoProto.KeyShare;
import com.aletheiaware.crypto.CryptoProto.SignatureAlgorithm;

import com.google.protobuf.ByteString;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

public final class BCUtils {

    public static final String TAG = "BC";

    public static final String BC_HOST = "bc.aletheiaware.com";
    public static final String BC_HOST_TEST = "test-bc.aletheiaware.com";

    private BCUtils() {}

    public static String getBCHostname(boolean debug) {
        return debug ? BC_HOST_TEST : BC_HOST;
    }

    public static int getOnes(byte[] data) {
        int ones = 0;
        for (byte b : data) {
            for (int i = 0; i < 8; i++) {
                if (((b >> i) & 1) > 0) {
                    ones++;
                }
            }
        }
        return ones;
    }

    /**
     * Register new customer.
     */
    public static String register(String url, String alias, String email, String paymentId) throws IOException {
        String params = "api=1&alias=" + URLEncoder.encode(alias, "utf-8")
                + "&stripeToken=" + URLEncoder.encode(paymentId, "utf-8")
                + "&stripeEmail=" + URLEncoder.encode(email, "utf-8");
        System.out.println("Params:" + params);
        return postForID(new URL(url), params.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Subscribe existing customer.
     */
    public static String subscribe(String url, String alias, String customerId) throws IOException {
        String params = "api=1&alias=" + URLEncoder.encode(alias, "utf-8")
                + "&customerId=" + URLEncoder.encode(customerId, "utf-8");
        System.out.println("Params:" + params);
        return postForID(new URL(url), params.getBytes(StandardCharsets.UTF_8));
    }

    public static String postForID(URL url, byte[] data) throws IOException {
        HttpsURLConnection conn = postForm(url, data);
        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        StringBuilder sb = new StringBuilder();
        if (response == HttpsURLConnection.HTTP_OK) {
            try (InputStream in = conn.getInputStream()) {
                Scanner s = new Scanner(in);
                while (s.hasNextLine()) {
                    sb.append(s.nextLine());
                    sb.append("\n");
                }
            }
            return sb.toString().trim();
        } else {
            try (InputStream err = conn.getErrorStream()) {
                Scanner s = new Scanner(err);
                while (s.hasNextLine()) {
                    sb.append(s.nextLine());
                    sb.append("\n");
                }
            }
            System.err.println("Error: " + sb.toString());
        }
        return null;
    }

    public static Reference postForReference(URL url, byte[] data) throws IOException {
        HttpsURLConnection conn = postForm(url, data);
        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        if (response == HttpsURLConnection.HTTP_OK) {
            try (InputStream in = conn.getInputStream()) {
                return Reference.parseDelimitedFrom(in);
            }
        } else {
            StringBuilder sb = new StringBuilder();
            try (InputStream err = conn.getErrorStream()) {
                Scanner s = new Scanner(err);
                while (s.hasNextLine()) {
                    sb.append(s.nextLine());
                    sb.append("\n");
                }
            }
            System.err.println("Error: " + sb.toString());
        }
        return null;
    }

    public static HttpsURLConnection postForm(URL url, byte[] data) throws IOException {
        System.out.println("URL: " + url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Keep-Alive", "timeout=60000");
        conn.setRequestProperty("Content-Length", Integer.toString(data.length));
        conn.setUseCaches(false);
        try (OutputStream out = conn.getOutputStream()) {
            out.write(data);
            out.flush();
        }
        return conn;
    }

    public interface RecordCallback {
        void onRecord(Record record);
    }

    public static long createEntries(String alias, KeyPair keys, Map<String, PublicKey> acl, List<Reference> references, InputStream in, RecordCallback callback) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        byte[] buffer = new byte[(int)BC.MAX_PAYLOAD_SIZE_BYTES];
        long size = 0L;
        int count;
        while ((count = in.read(buffer)) > 0) {
            size += count;
            byte[] payload = new byte[count];
            System.arraycopy(buffer, 0, payload, 0, count);
            Record record = createRecord(alias, keys, acl, references, payload);
            callback.onRecord(record);
        }
        return size;
    }

    public static Record createRecord(String alias, KeyPair keys, Map<String, PublicKey> acl, List<Reference> references, byte[] payload) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        if (payload.length > BC.MAX_PAYLOAD_SIZE_BYTES) {
            throw new IllegalArgumentException(String.format(BC.ERROR_PAYLOAD_TOO_LARGE, CommonUtils.binarySizeToString(payload.length), CommonUtils.binarySizeToString(BC.MAX_PAYLOAD_SIZE_BYTES)));
        }
        EncryptionAlgorithm encryption = EncryptionAlgorithm.UNKNOWN_ENCRYPTION;
        int as = acl.size();
        List<Record.Access> access = new ArrayList<>(as);
        // If Access Control List Declared
        if (as > 0) {
            // Set Encryption
            encryption = EncryptionAlgorithm.AES_GCM_NOPADDING;
            // Generate AES Key
            byte[] key = Crypto.generateSecretKey();
            // Encrypt Payload
            payload = Crypto.encryptAES(key, payload);
            // For each access
            for (String a : acl.keySet()) {
                // Encrypt AES Key with RSA Public Key
                byte[] k = Crypto.encryptRSA(acl.get(a), key);
                // Create Access
                access.add(Record.Access.newBuilder()
                        .setAlias(a)
                        .setSecretKey(ByteString.copyFrom(k))
                        .setEncryptionAlgorithm(EncryptionAlgorithm.RSA_ECB_OAEPPADDING)
                        .build());
            }
        }
        byte[] signature = Crypto.sign(keys.getPrivate(), payload);
        return Record.newBuilder()
                .setTimestamp(System.currentTimeMillis() * 1000000)// Convert milli to nano seconds
                .setCreator(alias)
                .addAllAccess(access)
                .setPayload(ByteString.copyFrom(payload))
                .setEncryptionAlgorithm(encryption)
                .setSignature(ByteString.copyFrom(signature))
                .setSignatureAlgorithm(SignatureAlgorithm.SHA512WITHRSA)
                .addAllReference(references)
                .build();
    }
}
