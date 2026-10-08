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

class HeadersCheckTest {

    private final HeadersCheck check = new HeadersCheck();

    private static PageSnapshot snap(String url, Map<String, List<String>> headers) {
        return new PageSnapshot(URI.create(url), 200, headers);
    }

    private static Map<String, List<String>> secureHeaders() {
        return Map.of(
                "Content-Security-Policy", List.of("default-src 'self'; frame-ancestors 'none'"),
                "Strict-Transport-Security", List.of("max-age=31536000"),
                "X-Content-Type-Options", List.of("nosniff"),
                "Referrer-Policy", List.of("no-referrer"));
    }

    private static List<String> titles(List<Finding> findings) {
        return findings.stream().map(Finding::title).toList();
    }

    @Test
    void fullySecureSiteHasNoFindings() {
        List<Finding> findings = check.run(snap("https://example.com", secureHeaders()));
        assertTrue(findings.isEmpty());
    }

    @Test
    void httpsSiteWithNoHeadersReportsEverything() {
        List<String> titles = titles(check.run(snap("https://example.com", Map.of())));

        assertEquals(5, titles.size());
        assertTrue(titles.contains("Missing Content-Security-Policy"));
        assertTrue(titles.contains("Missing Strict-Transport-Security"));
        assertTrue(titles.contains("Missing X-Content-Type-Options"));
        assertTrue(titles.contains("Missing Referrer-Policy"));
        assertTrue(titles.contains("Missing clickjacking protection"));
    }

    @Test
    void hstsIsNotRequiredOnPlainHttp() {
        List<String> titles = titles(check.run(snap("http://example.com", Map.of())));

        assertFalse(titles.contains("Missing Strict-Transport-Security"));
        assertEquals(4, titles.size());
    }

    @Test
    void xFrameOptionsSatisfiesClickjackingProtection() {
        Map<String, List<String>> headers = Map.of(
                "Content-Security-Policy", List.of("default-src 'self'"),
                "X-Frame-Options", List.of("DENY"),
                "Strict-Transport-Security", List.of("max-age=31536000"),
                "X-Content-Type-Options", List.of("nosniff"),
                "Referrer-Policy", List.of("no-referrer"));

        assertTrue(check.run(snap("https://example.com", headers)).isEmpty());
    }

    @Test
    void headerNamesAreCaseInsensitive() {
        Map<String, List<String>> headers = Map.of(
                "content-security-policy", List.of("default-src 'self'; frame-ancestors 'none'"),
                "strict-transport-security", List.of("max-age=31536000"),
                "x-content-type-options", List.of("nosniff"),
                "referrer-policy", List.of("no-referrer"));

        assertTrue(check.run(snap("https://example.com", headers)).isEmpty());
    }

    @Test
    void missingCspIsMediumSeverity() {
        List<Finding> findings = check.run(snap("https://example.com", Map.of()));

        Finding csp = findings.stream()
                .filter(f -> f.title().equals("Missing Content-Security-Policy"))
                .findFirst()
                .orElseThrow();

        assertEquals(Severity.MEDIUM, csp.severity());
        assertEquals("HeadersCheck", csp.checkName());
    }
}