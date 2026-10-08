package za.co.webscanner.model;

import java.util.Optional;

public record ParsedCookie(
        String name,
        boolean secure,
        boolean httpOnly,
        Optional<String> sameSite
) {

    public static ParsedCookie parse(String setCookieHeader) {
        String[] parts = setCookieHeader.split(";");

        String first = parts[0].trim();
        int eq = first.indexOf('=');
        String name = eq >= 0 ? first.substring(0, eq).trim() : first;

        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = null;

        for (int i = 1; i < parts.length; i++) {
            String attribute = parts[i].trim();
            int e = attribute.indexOf('=');
            String key = (e >= 0 ? attribute.substring(0, e) : attribute).trim().toLowerCase();
            String value = e >= 0 ? attribute.substring(e + 1).trim() : "";

            switch (key) {
                case "secure" -> secure = true;
                case "httponly" -> httpOnly = true;
                case "samesite" -> sameSite = value.toLowerCase();
                default -> {
                }
            }
        }

        return new ParsedCookie(name, secure, httpOnly, Optional.ofNullable(sameSite));
    }
}