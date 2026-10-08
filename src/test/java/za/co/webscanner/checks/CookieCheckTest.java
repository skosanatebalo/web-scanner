package za.co.webscanner.checks;

import org.junit.jupiter.api.Test;
import za.co.webscanner.model.Finding;
import za.co.webscanner.model.PageSnapshot;
import za.co.webscanner.model.Severity;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CookieCheckTest {

    private final CookieCheck check = new CookieCheck();

    private static PageSnapshot snap(String url, String... cookies) {
        Map<String, List<String>> headers =
                cookies.length == 0 ? Map.of() : Map.of("Set-Cookie", List.of(cookies));
        return new PageSnapshot(URI.create(url), 200, headers);
    }

    private static Finding find(List<Finding> findings, String titlePart) {
        return findings.stream()
                .filter(f -> f.title().contains(titlePart))
                .findFirst()
                .orElseThrow();
    }

    @Test
    void siteWithNoCookiesHasNoFindings() {
        assertTrue(check.run(snap("https://example.com")).isEmpty());
    }

    @Test
    void wellConfiguredCookieHasNoFindings() {
        List<Finding> findings = check.run(
                snap("https://example.com", "sessionid=abc; Secure; HttpOnly; SameSite=Lax"));
        assertTrue(findings.isEmpty());
    }

    @Test
    void sessionCookieWithNoFlagsReportsThreeFindings() {
        List<Finding> findings = check.run(snap("https://example.com", "sessionid=abc"));

        assertEquals(3, findings.size());
        assertEquals(Severity.HIGH, find(findings, "Secure flag").severity());
        assertEquals(Severity.HIGH, find(findings, "HttpOnly").severity());
        assertEquals(Severity.MEDIUM, find(findings, "SameSite").severity());
    }

    @Test
    void ordinaryCookieWithNoFlagsIsLowerSeverity() {
        List<Finding> findings = check.run(snap("https://example.com", "theme=dark"));

        assertEquals(3, findings.size());
        assertEquals(Severity.MEDIUM, find(findings, "Secure flag").severity());
        assertEquals(Severity.LOW, find(findings, "HttpOnly").severity());
        assertEquals(Severity.LOW, find(findings, "SameSite").severity());
    }

    @Test
    void secureFlagIsNotRequiredOnPlainHttp() {
        List<Finding> findings = check.run(
                snap("http://example.com", "sessionid=abc; HttpOnly; SameSite=Lax"));
        assertTrue(findings.isEmpty());
    }

    @Test
    void sameSiteNoneWithoutSecureIsFlagged() {
        List<Finding> findings = check.run(
                snap("https://example.com", "sessionid=abc; HttpOnly; SameSite=None"));

        assertEquals(2, findings.size());
        assertTrue(findings.stream().anyMatch(f -> f.title().contains("SameSite=None without Secure")));
    }

    @Test
    void eachCookieIsCheckedSeparately() {
        List<Finding> findings = check.run(snap("https://example.com",
                "sessionid=abc; Secure; HttpOnly; SameSite=Lax",
                "theme=dark"));

        assertEquals(3, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.title().contains("'theme'")));
    }

    @Test
    void cookieValuesNeverAppearInFindings() {
        List<Finding> findings = check.run(snap("https://example.com", "sessionid=SUPERSECRETVALUE"));

        for (Finding f : findings) {
            assertFalse(f.title().contains("SUPERSECRETVALUE"));
            assertFalse(f.description().contains("SUPERSECRETVALUE"));
            assertFalse(f.recommendation().contains("SUPERSECRETVALUE"));
        }
    }
}