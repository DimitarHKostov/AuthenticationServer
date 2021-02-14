package com.security.authentication.token;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TokenizerTest {
    @Test(expected = IllegalArgumentException.class)
    public void testSplitExpectedIllegalArgumentException() {
        Tokenizer.split(null);
    }

    @Test
    public void testSplitExpectedListOfOneToken() {
        List<String> actual = Tokenizer.split("token");
        List<String> expected = List.of("token");

        assertEquals("expecting only 1 token in the list", expected.size(), actual.size());

        assertTrue("only item is 1 token", actual.containsAll(expected) && expected.containsAll(actual));
    }

    @Test
    public void testSplitExpectedListOfManyToken() {
        List<String> actual = Tokenizer.split("token1 token2 token3 token4");
        List<String> expected = List.of("token1", "token2", "token3", "token4");

        assertEquals("expecting 4 tokens in the list", expected.size(), actual.size());

        assertTrue("4 items expected", actual.containsAll(expected) && expected.containsAll(actual));
    }
}
