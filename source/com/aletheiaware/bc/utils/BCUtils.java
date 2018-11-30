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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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

public final class BCUtils {

    public static final int AES_KEY_SIZE_BITS = 128;
    public static final int AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / 8;
    public static final int AES_IV_SIZE_BITS = 96;
    public static final int AES_IV_SIZE_BYTES = AES_IV_SIZE_BITS / 8;
    public static final int GCM_TAG_SIZE_BITS = 128;
    public static final int GCM_TAG_SIZE_BYTES = GCM_TAG_SIZE_BITS / 8;
    public static final int PBE_ITERATIONS = 10000;
    public static final int RSA_KEY_SIZE_BITS = 4096;

    public static final int PORT_BLOCK = 22222;
    public static final int PORT_HEAD = 22232;
    public static final int PORT_STATUS = 23222;
    public static final int PORT_WRITE = 23232;

    public static final String AES = "AES";
    public static final String AES_CIPHER = "AES/GCM/NoPadding"; //AES_128 // TODO AES/GCM/NoPadding on Android API 19 to 26
    public static final String HASH_DIGEST = "SHA-512";
    public static final String PBE_CIPHER = "PBKDF2WithHmacSHA1"; // TODO check Android compatibility
    public static final String RSA = "RSA";
    public static final String RSA_CIPHER = "RSA/ECB/OAEPPadding";
    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";// TODO check Go compatibility

    public static byte[] getHash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASH_DIGEST);
        digest.reset();
        return digest.digest(data);
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

    /*
     * Create a random AES secret key.
     */
    public static byte[] generateSecretKey(int size) {
        byte[] k = new byte[size];
        SecureRandom r = new SecureRandom();
        r.setSeed(System.currentTimeMillis());
        r.nextBytes(k);
        return k;
    }

    /**
     * Encrypts the data with the secret key.
     *
     * <p>Generates an initialization vector and prepends to the encrypted data result.</p>
     */
    public static byte[] encryptAES(byte[] key, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecureRandom r = new SecureRandom();
        r.setSeed(System.currentTimeMillis());

        // Create initialization vector
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        r.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);

        // Create AES Cipher
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, AES), gcmSpec);

        // Encrypt the data with the key
        byte[] encryptedData = cipher.doFinal(data);

        // Create result array
        byte[] result = new byte[AES_IV_SIZE_BYTES + encryptedData.length];
        // Copy iv to result
        System.arraycopy(iv, 0, result, 0, AES_IV_SIZE_BYTES);
        // Copy encrypted data to result
        System.arraycopy(encryptedData, 0, result, AES_IV_SIZE_BYTES, encryptedData.length);
        return result;
    }

    /**
     * Encrypts the data with the password.
     *
     * <p>Generates a salt and an initialization vector and prepends them to the encrypted data result.</p>
     */
    public static byte[] encryptAES(char[] password, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecureRandom r = new SecureRandom();
        r.setSeed(System.currentTimeMillis());

        // Create salt
        byte[] salt = new byte[AES_KEY_SIZE_BYTES];
        r.nextBytes(salt);

        // Create initialization vector
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        r.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);

        // Create PBE Key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_CIPHER);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, AES_KEY_SIZE_BITS);
        SecretKeySpec pbeKey = new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), AES);

        // Create AES Cipher
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, gcmSpec);

        // Encrypt the data with the PBE key
        byte[] encryptedData = cipher.doFinal(data);

        // Create result array
        byte[] result = new byte[AES_KEY_SIZE_BYTES + AES_IV_SIZE_BYTES + encryptedData.length];
        // Copy salt to result
        System.arraycopy(salt, 0, result, 0, AES_KEY_SIZE_BYTES);
        // Copy iv to result
        System.arraycopy(iv, 0, result, AES_KEY_SIZE_BYTES, AES_IV_SIZE_BYTES);
        // Copy encrypted data to result
        System.arraycopy(encryptedData, 0, result, AES_KEY_SIZE_BYTES + AES_IV_SIZE_BYTES, encryptedData.length);
        return result;
    }

    /**
     * Decrypts the data with the secret key.
     *
     * <p>Uses an initialization vector at the start of data.</p>
     */
    public static byte[] decryptAES(byte[] key, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        // Decrypt with the secret key
        SecretKeySpec secretKey = new SecretKeySpec(key, AES);
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        // Copy iv from data
        System.arraycopy(data, 0, iv, 0, AES_IV_SIZE_BYTES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
        int encryptedLength = data.length - AES_IV_SIZE_BYTES;
        byte[] encryptedData = new byte[encryptedLength];
        System.arraycopy(data, AES_IV_SIZE_BYTES, encryptedData, 0, encryptedLength);
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }

    /**
     * Decrypts the data with the password.
     *
     * <p>Uses a salt and an initialization vector at the start of data.</p>
     */
    public static byte[] decryptAES(char[] password, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] salt = new byte[AES_KEY_SIZE_BYTES];
        byte[] iv = new byte[AES_IV_SIZE_BYTES];
        // Copy salt from data
        System.arraycopy(data, 0, salt, 0, AES_KEY_SIZE_BYTES);
        // Copy iv from data
        System.arraycopy(data, AES_KEY_SIZE_BYTES, iv, 0, AES_IV_SIZE_BYTES);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv);
        // Copy encrypted payload from data
        int encryptedLength = data.length - AES_KEY_SIZE_BYTES - AES_IV_SIZE_BYTES;
        byte[] encryptedData = new byte[encryptedLength];
        System.arraycopy(data, AES_KEY_SIZE_BYTES + AES_IV_SIZE_BYTES, encryptedData, 0, encryptedLength);

        // Create PBE Key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_CIPHER);
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, PBE_ITERATIONS, AES_KEY_SIZE_BITS);
        SecretKeySpec pbeKey = new SecretKeySpec(factory.generateSecret(pbeSpec).getEncoded(), AES);

        // Create AES Cipher
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, gcmSpec);

        // Decrypt the data with the PBE key
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return decryptedData;
    }

    /*
     * Create a random RSA key pair.
     */
    public static KeyPair createRSAKeyPair(File directory, char[] password) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(RSA_KEY_SIZE_BITS);
        KeyPair pair = generator.genKeyPair();
        File privFile = new File(directory, "private.key");
        File pubFile = new File(directory, "public.key");
        writeFile(privFile, encryptAES(password, pair.getPrivate().getEncoded()));
        writeFile(pubFile, pair.getPublic().getEncoded());
        return pair;
    }

    public static boolean hasRSAKeyPair(File directory) {
        return new File(directory, "private.key").exists();
    }

    public static KeyPair getRSAKeyPair(File directory, char[] password) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        File privFile = new File(directory, "private.key");
        File pubFile = new File(directory, "public.key");
        byte[] privBytes = decryptAES(password, readFile(privFile));
        byte[] pubBytes = readFile(pubFile);
        PrivateKey privKey = KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        PublicKey pubKey = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(pubBytes));
        return new KeyPair(pubKey, privKey);
    }

    public static byte[] encryptRSA(PublicKey publicKey, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        OAEPParameterSpec params = new OAEPParameterSpec(HASH_DIGEST, "MGF1", new MGF1ParameterSpec(HASH_DIGEST), PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, params);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(PrivateKey privateKey, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER);
        OAEPParameterSpec params = new OAEPParameterSpec(HASH_DIGEST, "MGF1", new MGF1ParameterSpec(HASH_DIGEST), PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, params);
        return cipher.doFinal(data);
    }

    public static byte[] sign(PrivateKey key, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(PublicKey key, byte[] data, byte[] sig) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(key);
        signature.update(data);
        return signature.verify(sig);
    }

    public static byte[] readFile(File file) throws FileNotFoundException, IOException {
        FileInputStream in = null;
        byte[] data = null;
        if (file.exists()) {
            try {
                in = new FileInputStream(file);
                data = new byte[in.available()];
                in.read(data);
            } finally {
                if (in != null) {
                    in.close();
                }
            }
        }
        return data;
    }

    public static void writeFile(File file, byte[] data) throws FileNotFoundException, IOException {
        FileOutputStream out = null;
        try {
            file.createNewFile();
            out = new FileOutputStream(file);
            out.write(data);
            out.flush();
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
}
