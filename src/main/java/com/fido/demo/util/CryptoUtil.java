package com.fido.demo.util;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

import static com.fido.demo.util.CommonConstants.SESSION_ID_DEFAULT_LENGTH;


@Component
public class CryptoUtil {

    public String getRandmString() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[SESSION_ID_DEFAULT_LENGTH];
        secureRandom.nextBytes(randomBytes);  // Fill the byte array with random bytes

        return new String(randomBytes);
    }

    public String getRandomBase64String(){
        return this.getRandomBase64String(SESSION_ID_DEFAULT_LENGTH);
    }

    public String getRandomBase64String(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);  // Fill the byte array with random bytes

        // Encode the random bytes to a string using Base64 (or Hex, depending on your preference)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

}
