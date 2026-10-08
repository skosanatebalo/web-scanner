package za.co.webscanner.model;

public record Finding (
        String checkName,
        Severity severity,
        String title,
        String description,
        String recommendation
){}
