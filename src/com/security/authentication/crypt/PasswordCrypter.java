package com.security.authentication.crypt;

import com.security.authentication.exceptions.crypt.CypherInitializeFailException;
import com.security.authentication.exceptions.crypt.DecryptFailException;
import com.security.authentication.exceptions.crypt.EncryptFailException;
import com.security.authentication.validator.Validator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordCrypter implements Encrypter, Decrypter {
    private final SecretKey secretKey;
    private final Cipher cypher;

    {
        try {
            cypher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CypherInitializeFailException("cypher initializing failed", e);
        }
    }

    public PasswordCrypter(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public String decrypt(String word) throws DecryptFailException {
        Validator.validateNotNull(word, "word");

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(word);

        byte[] decryptedByte;

        try {
            cypher.init(Cipher.DECRYPT_MODE, secretKey);
            decryptedByte = cypher.doFinal(encryptedTextByte);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new DecryptFailException("problem occurred during decrypting");
        }

        return new String(decryptedByte);
    }

    @Override
    public String encrypt(String word) throws EncryptFailException {
        Validator.validateNotNull(word, "word");

        byte[] encryptedByte;

        try {
            byte[] plainTextByte = word.getBytes(StandardCharsets.UTF_8);
            cypher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptedByte = cypher.doFinal(plainTextByte);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new EncryptFailException("problem occurred during encrypting");
        }

        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(encryptedByte);
    }
}
