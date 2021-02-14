package com.security.authentication.generator;

import com.security.authentication.exceptions.crypt.KeyGeneratorInitializeFailException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class SecretKeyGenerator implements Generator<SecretKey> {
    @Override
    public SecretKey generate() {
        KeyGenerator keyGenerator;

        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGeneratorInitializeFailException("key initializing failed", e);
        }

        keyGenerator.init(128);

        return keyGenerator.generateKey();
    }
}
