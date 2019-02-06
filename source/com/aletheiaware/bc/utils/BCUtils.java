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

import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.KeyShare;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.BCProto.SignatureAlgorithm;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.InvocationTargetException;
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
    public static final int PORT_HEAD = 22322;
    public static final int PORT_WRITE = 23232;

    public static final String AES = "AES";
    public static final String AES_CIPHER = "AES/GCM/NoPadding";
    public static final String HASH_DIGEST = "SHA-512";
    public static final String PBE_CIPHER = "PBKDF2WithHmacSHA1";
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

    public static Reference getHead(InetAddress address, Reference reference) throws IOException {
        Socket s = new Socket(address, PORT_HEAD);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        reference.writeDelimitedTo(out);
        out.flush();
        return Reference.parseDelimitedFrom(in);
    }

    public static Block getBlock(InetAddress address, Reference reference) throws IOException {
        Socket s = new Socket(address, PORT_BLOCK);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        reference.writeDelimitedTo(out);
        out.flush();
        return Block.parseDelimitedFrom(in);
    }

    public static byte[] encodeBase64(byte[] data) {
        try {
            return java.util.Base64.getEncoder().encode(data);
        } catch (java.lang.NoClassDefFoundError e) {
            try {
                // Android doesn't have java.util.Base64, try android.util.Base64
                Class<?> c = Class.forName("android.util.Base64");
                java.lang.reflect.Method m = c.getDeclaredMethod("encode", byte[].class, int.class);
                return (byte[]) m.invoke(null, data, 0);
            } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                ex.printStackTrace();
                throw e; // Throw original exception
            }
        }
    }

    public static byte[] encodeBase64URL(byte[] data) {
        try {
            return java.util.Base64.getUrlEncoder().withoutPadding().encode(data);
        } catch (java.lang.NoClassDefFoundError e) {
            try {
                // Android doesn't have java.util.Base64, try android.util.Base64
                Class<?> c = Class.forName("android.util.Base64");
                int urlSafe = c.getDeclaredField("URL_SAFE").getInt(null);
                int noWrap = c.getDeclaredField("NO_WRAP").getInt(null);
                int noPadding = c.getDeclaredField("NO_PADDING").getInt(null);
                int flag = urlSafe | noWrap | noPadding;
                java.lang.reflect.Method m = c.getDeclaredMethod("encode", byte[].class, int.class);
                return (byte[]) m.invoke(null, data, (Integer) flag);
            } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | NoSuchFieldException | NoSuchMethodException ex) {
                ex.printStackTrace();
                throw e; // Throw original exception
            }
        }
    }

    public static byte[] decodeBase64(byte[] base64) {
        try {
            return java.util.Base64.getDecoder().decode(base64);
        } catch (java.lang.NoClassDefFoundError e) {
            try {
                // Android doesn't have java.util.Base64, try android.util.Base64
                Class<?> c = Class.forName("android.util.Base64");
                java.lang.reflect.Method m = c.getDeclaredMethod("decode", byte[].class, int.class);
                return (byte[]) m.invoke(null, base64, 0);
            } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                ex.printStackTrace();
                throw e; // Throw original exception
            }
        }
    }

    public static byte[] decodeBase64URL(byte[] base64) {
        try {
            return java.util.Base64.getUrlDecoder().decode(base64);
        } catch (java.lang.NoClassDefFoundError e) {
            try {
                // Android doesn't have java.util.Base64, try android.util.Base64
                Class<?> c = Class.forName("android.util.Base64");
                int urlSafe = c.getDeclaredField("URL_SAFE").getInt(null);
                int noWrap = c.getDeclaredField("NO_WRAP").getInt(null);
                int noPadding = c.getDeclaredField("NO_PADDING").getInt(null);
                int flag = urlSafe | noWrap | noPadding;
                java.lang.reflect.Method m = c.getDeclaredMethod("decode", byte[].class, int.class);
                return (byte[]) m.invoke(null, base64, (Integer) flag);
            } catch (ClassNotFoundException | IllegalAccessException | InvocationTargetException | NoSuchFieldException | NoSuchMethodException ex) {
                ex.printStackTrace();
                throw e; // Throw original exception
            }
        }
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
        byte[] encryptedData = cipher.doFinal(data);// TODO switch to streams

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
    public static KeyPair createRSAKeyPair(File directory, String alias, char[] password) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        System.out.println("Creating " + RSA_KEY_SIZE_BITS + "bit " + RSA + " key pair: " + alias);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
        generator.initialize(RSA_KEY_SIZE_BITS);
        KeyPair pair = generator.genKeyPair();
        writeRSAKeyPair(directory, alias, password, pair);
        return pair;
    }

    /*
     * Create an RSA key pair from the given private key format and bytes.
     */
    public static KeyPair importRSAKeyPair(File directory, String accessCode, KeyShare ks) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        System.out.println("KeyShare: " + ks);
        byte[] key = decodeBase64URL(accessCode.getBytes("utf-8"));
        KeySpec publicSpec = null;
        byte[] pub = ks.getPublicKey().toByteArray();
        switch (ks.getPublicFormat()) {
            case X509:
                publicSpec = new X509EncodedKeySpec(pub);
                break;
            case UNKNOWN_PUBLIC_KEY_FORMAT:
            default:
                throw new IOException("Unknown public key format");
        }
        KeySpec privateSpec = null;
        byte[] priv = decryptAES(key, ks.getPrivateKey().toByteArray());
        switch (ks.getPrivateFormat()) {
            case PKCS8:
                privateSpec = new PKCS8EncodedKeySpec(priv);
                break;
            case UNKNOWN_PRIVATE_KEY_FORMAT:
            default:
                throw new IOException("Unknown private key format");
        }
        PrivateKey privateKey = KeyFactory.getInstance(RSA).generatePrivate(privateSpec);
        PublicKey publicKey = KeyFactory.getInstance(RSA).generatePublic(publicSpec);
        KeyPair pair = new KeyPair(publicKey, privateKey);
        char[] password = new String(decryptAES(key, ks.getPassword().toByteArray())).toCharArray();
        System.out.println("Password: " + password);
        writeRSAKeyPair(directory, ks.getAlias(), password, pair);
        return pair;
    }

    /*
     * Write an RSA key pair to files.
     */
    public static void writeRSAKeyPair(File directory, String alias, char[] password, KeyPair pair) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] privateKeyBytes = pair.getPrivate().getEncoded();
        byte[] publicKeyBytes = pair.getPublic().getEncoded();
        if (alias == null || alias.isEmpty()) {
            alias = new String(encodeBase64URL(getHash(publicKeyBytes)));
        }
        File privFile = new File(directory, alias + ".priv");
        File pubFile = new File(directory, alias + ".pub");
        writeFile(privFile, encryptAES(password, privateKeyBytes));
        writeFile(pubFile, publicKeyBytes);
    }

    /**
     * Registers the alias and public key (private key used for signature).
     */
    public static void registerAlias(String alias, KeyPair keys) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" + new String(encodeBase64(keys.getPublic().getEncoded())) + "\n-----END PUBLIC KEY-----\n";
        String publicKeyFormat = keys.getPublic().getFormat();
        byte[] signature = sign(keys.getPrivate(), (alias + "\n" + publicKey).getBytes(StandardCharsets.UTF_8));
        String params = "alias=" + URLEncoder.encode(alias, "utf-8")
                + "&publicKey=" + URLEncoder.encode(publicKey, "utf-8")
                + "&publicKeyFormat=" + URLEncoder.encode(publicKeyFormat, "utf-8")
                + "&signature=" + URLEncoder.encode(new String(encodeBase64URL(signature)), "utf-8")
                + "&signatureAlgorithm=" + URLEncoder.encode(SignatureAlgorithm.SHA512WITHRSA.toString(), "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);
        //TODO URL url = new URL("https://bc.aletheiaware.com:443/alias");
        //TODO HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        URL url = new URL("http://bc.aletheiaware.com/alias");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Content-Length", Integer.toString(data.length));
        conn.setUseCaches(false);
        try (OutputStream o = conn.getOutputStream()) {
            o.write(data);
            o.flush();
        }

        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        Scanner in = new Scanner(conn.getInputStream());
        while (in.hasNextLine()) {
            System.out.println(in.nextLine());
        }
    }

    public static boolean deleteRSAKeyPair(File directory, String alias) {
        return new File(directory, alias + ".priv").delete()
                && new File(directory, alias + ".pub").delete();
    }

    public static List<String> listRSAKeyPairs(File directory) {
        List<String> aliases = new ArrayList<>();
        for (String f : directory.list()) {
            int index = f.lastIndexOf('.');
            if (index > 0 && f.substring(index + 1).equals("priv")) {
                aliases.add(f.substring(0, index));
            }
        }
        return aliases;
    }

    public static KeyPair getRSAKeyPair(File directory, String alias, char[] password) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        File privFile = new File(directory, alias + ".priv");
        File pubFile = new File(directory, alias + ".pub");
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

    public static class Pair<A, B> {
        public A a;
        public B b;
        public Pair(A a, B b) {
            this.a = a;
            this.b = b;
        }
    }
}