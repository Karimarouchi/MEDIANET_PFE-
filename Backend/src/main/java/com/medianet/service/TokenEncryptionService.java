package com.medianet.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class TokenEncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_SIZE = 12;

    @Value("${token.encryption.key:}")
    private String encryptionKeyBase64;

    @Value("${jwt.secret}")
    private String jwtSecret;

    private SecretKey secretKey;
    private final SecureRandom secureRandom = new SecureRandom();

    @PostConstruct
    void init() {
        byte[] keyBytes;
        if (encryptionKeyBase64 != null && !encryptionKeyBase64.isBlank()) {
            keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
        } else {
            byte[] fallback = jwtSecret.getBytes(StandardCharsets.UTF_8);
            keyBytes = java.util.Arrays.copyOf(fallback, 32);
        }
        if (keyBytes.length != 32) {
            keyBytes = java.util.Arrays.copyOf(keyBytes, 32);
        }
        secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
            byte[] payload = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt token", e);
        }
    }

    public String decrypt(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            byte[] payload = Base64.getDecoder().decode(value);
            byte[] iv = java.util.Arrays.copyOfRange(payload, 0, IV_SIZE);
            byte[] encrypted = java.util.Arrays.copyOfRange(payload, IV_SIZE, payload.length);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt token", e);
        }
    }
}