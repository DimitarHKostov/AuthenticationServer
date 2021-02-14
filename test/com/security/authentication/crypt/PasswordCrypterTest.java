package com.security.authentication.crypt;

import com.security.authentication.exceptions.crypt.DecryptFailException;
import com.security.authentication.exceptions.crypt.EncryptFailException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.crypto.SecretKey;

@RunWith(MockitoJUnitRunner.class)
public class PasswordCrypterTest {
    @Mock
    private SecretKey secretKey;

    @InjectMocks
    private PasswordCrypter passwordCrypter;

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptExpectedIllegalArgumentException() throws EncryptFailException {
        passwordCrypter.encrypt(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptExpectedIllegalArgumentException() throws DecryptFailException {
        passwordCrypter.decrypt(null);
    }
}
