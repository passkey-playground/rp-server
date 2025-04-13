package com.fido.demo.util;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

@Component
public class Base64Utils {

    private static final Pattern BASE64URL_PATTERN = Pattern.compile("^[A-Za-z0-9_-]*$");

    public byte[] decodeURLAsBytes(String input) {
        byte[] bytes = Base64.getUrlDecoder().decode(input);
        return bytes;
    }

    public String decodeAsString(String input) {
        byte[] bytes = Base64.getDecoder().decode(input);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public byte[] decodeAsBytea(String input) {
        byte[] bytes = Base64.getDecoder().decode(input);
        return  bytes;
    }

    public byte[] validateAndDecodeCredentialId(String credentialId) {
        // Check if ID is null or empty
        if (credentialId == null) {
            throw new IllegalArgumentException("Credential ID cannot be null");
        }

        if (credentialId.isEmpty()) {
            throw new IllegalArgumentException("Credential ID cannot be empty");
        }

        // Validate that it contains only base64url characters
        if (!BASE64URL_PATTERN.matcher(credentialId).matches()) {
            throw new IllegalArgumentException("Credential ID contains invalid characters, must be base64url encoded");
        }

        // Decode the base64url string to get the raw credential ID bytes
        try {
            // Use Base64.getUrlDecoder() for base64url decoding
            return Base64.getUrlDecoder().decode(credentialId);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Credential ID is not valid base64url: " + e.getMessage(), e);
        }
    }
}
