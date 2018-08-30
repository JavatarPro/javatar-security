package pro.javatar.security.oidc.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

class UrlFilterAnalyzer {
    private Pattern applyAsContainingPattern;
    private Pattern applyAsStartingPattern;

    UrlFilterAnalyzer() {
        this.applyAsContainingPattern = Pattern.compile("^\\*(.+)\\*.*");
        this.applyAsStartingPattern = Pattern.compile("^(.+)\\*.*");
    }

    String getApplyAsContainingFilter(String filter) {
        Matcher matcher = applyAsContainingPattern.matcher(filter);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        return null;
    }

    String getApplyAsStartingFilter(String filter) {
        Matcher matcher = applyAsStartingPattern.matcher(filter);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        return null;
    }
}
