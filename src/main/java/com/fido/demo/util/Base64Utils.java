package com.fido.demo.util;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class Base64Utils {


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

}
