package za.co.webscanner.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ParsedCookieTest {

    @Test
    void parsesAllFlags() {
        ParsedCookie c = ParsedCookie.parse("sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax");

        assertEquals("sessionid", c.name());
        assertTrue(c.secure());
        assertTrue(c.httpOnly());
        assertEquals("lax", c.sameSite().orElseThrow());
    }

    @Test
    void parsesBareCookieWithNoFlags() {
        ParsedCookie c = ParsedCookie.parse("theme=dark");

        assertEquals("theme", c.name());
        assertFalse(c.secure());
        assertFalse(c.httpOnly());
        assertTrue(c.sameSite().isEmpty());
    }

    @Test
    void attributeNamesAreCaseInsensitive() {
        ParsedCookie c = ParsedCookie.parse("id=1; SECURE; httponly; SAMESITE=Strict");

        assertTrue(c.secure());
        assertTrue(c.httpOnly());
        assertEquals("strict", c.sameSite().orElseThrow());
    }

    @Test
    void valueContainingEqualsSignDoesNotBreakParsing() {
        ParsedCookie c = ParsedCookie.parse("token=abc==; Secure");

        assertEquals("token", c.name());
        assertTrue(c.secure());
    }
}