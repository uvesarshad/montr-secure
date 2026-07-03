package com.example.vuln.util;

import java.security.MessageDigest;

/**
 * corpus: jvm-vuln — password hashing helper. DO NOT DEPLOY.
 * Planted: A02:2021 Weak Cryptography (MD5 for password hashing).
 */
public final class HashUtil {

    private HashUtil() {
    }

    // A02:2021 — MD5 is a broken hash for credential storage (fast + collidable).
    public static byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes("UTF-8"));
    }
}
