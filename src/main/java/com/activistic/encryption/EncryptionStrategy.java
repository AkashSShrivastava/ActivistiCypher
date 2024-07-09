package com.activistic.encryption;

public interface EncryptionStrategy {
    String encrypt(String plaintext) throws Exception;
    String decrypt(String encryptedText) throws Exception;
}
