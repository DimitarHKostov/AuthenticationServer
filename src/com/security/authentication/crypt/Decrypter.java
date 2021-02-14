package com.security.authentication.crypt;

import com.security.authentication.exceptions.crypt.DecryptFailException;

public interface Decrypter extends Crypter {
    String decrypt(String word) throws DecryptFailException;
}
