package za.co.webscanner.checks;

import za.co.webscanner.model.Finding;
import za.co.webscanner.model.PageSnapshot;

import java.util.List;

public interface Check {

    String name();

    List<Finding> run(PageSnapshot snapshot);
}