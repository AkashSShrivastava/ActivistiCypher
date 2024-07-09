package com.activistic.encryption.impl;

import com.activistic.encryption.EncryptionStrategy;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class CustomEncryptionUtil implements EncryptionStrategy {
    private static final String OPENSSL_PATH = "openssl"; // Assumes openssl is in your PATH

    private final String encryptionKey;
    private final String algorithm;

    public CustomEncryptionUtil(String encryptionKey, String algorithm) {
        this.encryptionKey = encryptionKey;
        this.algorithm = algorithm;
    }

    private String getEncryptionCommandTemplate() {
        return String.format("%s enc -%s -pbkdf2 -a -salt -pass pass:%%s", OPENSSL_PATH, algorithm);
    }

    private String getDecryptionCommandTemplate() {
        return String.format("%s enc -d -%s -pbkdf2 -a -salt -pass pass:%%s", OPENSSL_PATH, algorithm);
    }

    @Override
    public String encrypt(String plaintext) throws Exception {
        String command = String.format(getEncryptionCommandTemplate(), encryptionKey);
        ProcessBuilder encryptPb;
        if (isWindows()) {
            encryptPb = new ProcessBuilder("cmd.exe", "/c", "echo " + plaintext + " | " + command);
        } else {
            encryptPb = new ProcessBuilder("/bin/sh", "-c", "echo -n \"" + plaintext + "\" | " + command);
        }
        Process encryptProcess = encryptPb.start();
        String output = getProcessOutput(encryptProcess);
        encryptProcess.waitFor();
        return output.trim();
    }

    @Override
    public String decrypt(String encryptedText) throws Exception {
        String command = String.format(getDecryptionCommandTemplate(), encryptionKey);
        ProcessBuilder decryptPb;
        if (isWindows()) {
            decryptPb = new ProcessBuilder("cmd.exe", "/c", "echo " + encryptedText + " | " + command);
        } else {
            decryptPb = new ProcessBuilder("/bin/sh", "-c", "echo \"" + encryptedText + "\" | " + command);
        }
        Process decryptProcess = decryptPb.start();
        int exitCode = decryptProcess.waitFor();
        if (exitCode == 0) {
            return getProcessOutput(decryptProcess).trim();
        } else {
            String errorOutput = getProcessErrorOutput(decryptProcess);
            throw new Exception("Decryption failed with exit code " + exitCode + ". Error: " + errorOutput);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    private static String getProcessOutput(Process process) throws Exception {
        return getProcessStream(process.getInputStream());
    }

    private static String getProcessErrorOutput(Process process) throws Exception {
        return getProcessStream(process.getErrorStream());
    }

    private static String getProcessStream(InputStream inputStream) throws Exception {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        return output.toString();
    }
}

