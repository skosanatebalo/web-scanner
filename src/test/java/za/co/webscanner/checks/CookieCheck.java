package za.co.webscanner.checks;

import za.co.webscanner.model.Finding;
import za.co.webscanner.model.PageSnapshot;
import za.co.webscanner.model.ParsedCookie;
import za.co.webscanner.model.Severity;

import java.util.ArrayList;
import java.util.List;

public class CookieCheck implements Check {

    private static final List<String> SESSION_HINTS =
            List.of("session", "sess", "sid", "token", "auth", "jwt", "login");

    @Override
    public String name() {
        return "CookieCheck";
    }

    @Override
    public List<Finding> run(PageSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        boolean isHttps = "https".equalsIgnoreCase(snapshot.url().getScheme());

        for (String header : snapshot.headerValues("Set-Cookie")) {
            ParsedCookie cookie = ParsedCookie.parse(header);
            boolean sessionLike = looksLikeSession(cookie.name());

            if (isHttps && !cookie.secure()) {
                findings.add(new Finding(
                        name(),
                        sessionLike ? Severity.HIGH : Severity.MEDIUM,
                        "Cookie '" + cookie.name() + "' is missing the Secure flag",
                        "The browser may send this cookie over plain HTTP, where anyone on the "
                                + "network path can read it.",
                        "Add the Secure attribute to the Set-Cookie header."));
            }

            if (!cookie.httpOnly()) {
                findings.add(new Finding(
                        name(),
                        sessionLike ? Severity.HIGH : Severity.LOW,
                        "Cookie '" + cookie.name() + "' is missing the HttpOnly flag",
                        "JavaScript on the page can read this cookie, so a cross-site scripting "
                                + "bug could be used to steal it.",
                        "Add the HttpOnly attribute unless scripts genuinely need to read this cookie."));
            }

            if (cookie.sameSite().isEmpty()) {
                findings.add(new Finding(
                        name(),
                        sessionLike ? Severity.MEDIUM : Severity.LOW,
                        "Cookie '" + cookie.name() + "' has no SameSite attribute",
                        "Without SameSite, behavior depends on the browser's default. Setting it "
                                + "explicitly limits cross-site request forgery (CSRF).",
                        "Add SameSite=Lax (or Strict for sensitive cookies)."));
            } else if (cookie.sameSite().get().equals("none") && !cookie.secure()) {
                findings.add(new Finding(
                        name(),
                        Severity.MEDIUM,
                        "Cookie '" + cookie.name() + "' uses SameSite=None without Secure",
                        "Browsers require Secure alongside SameSite=None and may reject the cookie.",
                        "Add the Secure attribute, or use SameSite=Lax."));
            }
        }

        return findings;
    }

    private boolean looksLikeSession(String cookieName) {
        String lower = cookieName.toLowerCase();
        return SESSION_HINTS.stream().anyMatch(lower::contains);
    }
}