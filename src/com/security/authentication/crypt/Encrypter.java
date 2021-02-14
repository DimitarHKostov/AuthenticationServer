package com.security.authentication.crypt;

import com.security.authentication.exceptions.crypt.EncryptFailException;

public interface Encrypter extends Crypter {
    String encrypt(String word) throws EncryptFailException;
}
