package org.morandi.proxy;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class PrivateStore {
    private static final String KEY_ALIAS = "org.morandi.proxy.vault.1";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    private static final int IV_SIZE = 12;
    private final SharedPreferences values;

    PrivateStore(Context context) {
        values = context.getSharedPreferences("proxy_session_v1", Context.MODE_PRIVATE);
    }

    static String accountSlot(String username) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(username.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        return "device." + Base64.encodeToString(digest, Base64.NO_WRAP | Base64.URL_SAFE);
    }

    void warmKey() {
        try {
            // Only an empty vault can acquire a new master key during warmup.
            key(values.getAll().isEmpty());
        } catch (Exception ignored) {
            // Login will retry through the normal durable key write.
        }
    }

    String read(String slot) throws Exception {
        String stored = values.getString(slot, null);
        if (stored == null) {
            return "";
        }
        byte[] encrypted = Base64.decode(stored, Base64.NO_WRAP);
        if (encrypted.length <= IV_SIZE + 16 || encrypted.length > 4096) {
            throw new IOException("PRIVATE_STORE_INVALID");
        }
        GCMParameterSpec parameters = new GCMParameterSpec(128, encrypted, 0, IV_SIZE);
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, key(false), parameters);
        cipher.updateAAD(slot.getBytes(StandardCharsets.UTF_8));
        byte[] plaintext = cipher.doFinal(encrypted, IV_SIZE, encrypted.length - IV_SIZE);
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    void write(String slot, String value) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, key(true));
        cipher.updateAAD(slot.getBytes(StandardCharsets.UTF_8));
        byte[] iv = cipher.getIV();
        if (iv.length != IV_SIZE) {
            throw new IOException("PRIVATE_STORE_INVALID");
        }
        byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] record = ByteBuffer.allocate(iv.length + ciphertext.length)
                    .put(iv).put(ciphertext).array();
            if (!values.edit().putString(slot, Base64.encodeToString(record, Base64.NO_WRAP)).commit()) {
                throw new IOException("PRIVATE_STORE_UNAVAILABLE");
            }
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    void remove(String... slots) throws IOException {
        SharedPreferences.Editor editor = values.edit();
        for (String slot : slots) {
            editor.remove(slot);
        }
        if (!editor.commit()) {
            throw new IOException("PRIVATE_STORE_UNAVAILABLE");
        }
    }

    private static synchronized SecretKey key(boolean create) throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.getKey(KEY_ALIAS, null) instanceof SecretKey secret) {
            return secret;
        }
        if (!create) {
            throw new IOException("PRIVATE_STORE_UNAVAILABLE");
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }
}
