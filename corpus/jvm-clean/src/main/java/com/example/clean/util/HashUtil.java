package com.example.clean.util;

import java.security.MessageDigest;

/** corpus: jvm-clean — password digest helper using a strong hash. */
public final class HashUtil {

    private HashUtil() {
    }

    public static byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(password.getBytes("UTF-8"));
    }
}
