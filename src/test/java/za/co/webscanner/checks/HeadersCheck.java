package za.co.webscanner.checks;

import za.co.webscanner.model.Finding;
import za.co.webscanner.model.PageSnapshot;
import za.co.webscanner.model.Severity;

import java.util.ArrayList;
import java.util.List;

public class HeadersCheck implements Check {

    private record HeaderRule(String header, Severity severity, boolean httpsOnly, String description, String recommendation) {
    }

    private static final List<HeaderRule> RULES = List.of(
            new HeaderRule(
                    "Content-Security-Policy", Severity.MEDIUM, false,
                    "Without a CSP, the browser has no rules limiting where scripts and other "
                            + "content can load from, which makes cross-site scripting (XSS) easier to exploit.",
                    "Add a Content-Security-Policy header. Start strict, for example "
                            + "default-src 'self', and loosen only what the site needs."),
            new HeaderRule(
                    "Strict-Transport-Security", Severity.MEDIUM, true,
                    "Without HSTS, browsers can be tricked into using plain HTTP on later visits, "
                            + "which allows downgrade and interception attacks.",
                    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            new HeaderRule(
                    "X-Content-Type-Options", Severity.LOW, false,
                    "Browsers may guess a file's type instead of trusting the declared one "
                            + "(MIME sniffing), which can turn an uploaded file into executable script.",
                    "Add X-Content-Type-Options: nosniff"),
            new HeaderRule(
                    "Referrer-Policy", Severity.LOW, false,
                    "Without a policy, the full URL (possibly with tokens or private paths) may be "
                            + "sent to other sites when users click links.",
                    "Add Referrer-Policy: strict-origin-when-cross-origin, or something stricter.")
    );

    @Override
    public String name() {
        return "HeadersCheck";
    }

    @Override
    public List<Finding> run(PageSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        boolean isHttps = "https".equalsIgnoreCase(snapshot.url().getScheme());

        for (HeaderRule rule : RULES) {
            if (rule.httpsOnly() && !isHttps) {
                continue;
            }
            if (snapshot.header(rule.header()).isEmpty()) {
                findings.add(new Finding(
                        name(),
                        rule.severity(),
                        "Missing " + rule.header(),
                        rule.description(),
                        rule.recommendation()));
            }
        }

        checkClickjacking(snapshot, findings);
        return findings;
    }

    private void checkClickjacking(PageSnapshot snapshot, List<Finding> findings) {
        boolean hasFrameOptions = snapshot.header("X-Frame-Options").isPresent();
        boolean hasFrameAncestors = snapshot.header("Content-Security-Policy")
                .map(csp -> csp.toLowerCase().contains("frame-ancestors"))
                .orElse(false);

        if (!hasFrameOptions && !hasFrameAncestors) {
            findings.add(new Finding(
                    name(),
                    Severity.MEDIUM,
                    "Missing clickjacking protection",
                    "The page can be embedded in another site's frame, letting attackers trick "
                            + "users into clicking hidden buttons (clickjacking).",
                    "Add X-Frame-Options: DENY, or a CSP with frame-ancestors 'none' or 'self'."));
        }
    }
}