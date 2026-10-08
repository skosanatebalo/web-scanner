package za.co.webscanner.model;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

public record PageSnapshot(
        URI url,
        int statusCode,
        Map<String, List<String>> headers
) {

    public PageSnapshot {
        Map<String, List<String>> caseInsensitive = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitive.putAll(headers);
        headers = Collections.unmodifiableMap(caseInsensitive);
    }

    public Optional<String> header(String name) {
        List<String> values = headers.get(name);
        if (values == null || values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(values.get(0));
    }

    public List<String> headerValues(String name) {
        return headers.getOrDefault(name, List.of());
    }
}