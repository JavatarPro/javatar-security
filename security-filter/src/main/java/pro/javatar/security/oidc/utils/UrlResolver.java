package pro.javatar.security.oidc.utils;

import pro.javatar.security.oidc.filters.uri.UriFilterOption;
import pro.javatar.security.oidc.filters.uri.UriPredicate;

import org.springframework.http.HttpRequest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UrlResolver {
    private static final String WILDCARD_SEARCH_SYMBOL = "*";

    private Pattern applyPattern;

    private List<UriFilterOption> applyFilters = new ArrayList<>();
    private Set<UriFilterOption> applyAsEquality = new HashSet<>();
    private Set<UriFilterOption> applyAsStarting = new HashSet<>();
    private Set<UriFilterOption> applyAsContaining = new HashSet<>();

    private List<UriFilterOption> ignoreFilters = new ArrayList<>();
    private Set<UriFilterOption> ignoreAsEquality = new HashSet<>();
    private Set<UriFilterOption> ignoreAsStarting = new HashSet<>();
    private Set<UriFilterOption> ignoreAsContaining = new HashSet<>();

    private UrlFilterAnalyzer urlFilterAnalyzer;

    public UrlResolver() {
        this.urlFilterAnalyzer = new UrlFilterAnalyzer();
    }

    public UrlResolver(String filterApplyUrlRegex, List<UriFilterOption> applyFilters, List<UriFilterOption> ignoreFilters) {
        this();

        setFilterApplyUrlRegex(filterApplyUrlRegex);
        setFilterIgnoreUrls(ignoreFilters);
        setFilterApplyUrls(applyFilters);
    }

    public boolean apply(HttpRequest request) {
        if (isEmpty()) {
            return true;
        }

        if (ignoreAsContaining.stream()
                 .anyMatch(UriPredicate.uriContains(request)
                         .and(UriPredicate.httpMethodEquals(request)))) {
            return false;
        }
        if (ignoreAsStarting.stream()
                     .anyMatch(UriPredicate.uriStarts(request)
                             .and(UriPredicate.httpMethodEquals(request)))) {
            return false;
        }
        if (ignoreAsEquality.stream()
                     .anyMatch(UriPredicate.uriEquals(request)
                             .and(UriPredicate.httpMethodEquals(request)))) {
            return false;
        }
        if (applyAsContaining.stream()
                .anyMatch(UriPredicate.uriContains(request)
                        .and(UriPredicate.httpMethodEquals(request)))) {
            return true;
        }
        if (applyAsStarting.stream()
                .anyMatch(UriPredicate.uriStarts(request)
                        .and(UriPredicate.httpMethodEquals(request)))) {
            return true;
        }
        if (applyAsEquality.stream()
                .anyMatch(UriPredicate.uriEquals(request)
                        .and(UriPredicate.httpMethodEquals(request)))) {
            return true;
        }

        if (applyPattern == null) {
            return false;
        }
        Matcher matcher = applyPattern.matcher(request.getURI().getPath());
        return matcher.matches();
    }

    public boolean skip(HttpRequest request) {
        return !apply(request);
    }

    public void setFilterApplyUrlRegex(String filterApplyUrlRegex) {
        this.applyPattern = null;
        if (StringUtils.isNotBlank(filterApplyUrlRegex)) {
            this.applyPattern = Pattern.compile(filterApplyUrlRegex, Pattern.CASE_INSENSITIVE);
        }
    }

    public void setFilterIgnoreUrls(List<UriFilterOption> filters) {
        clearIgnoreFilters();
        decomposeFiltersByPurpose(filters, ignoreFilters, ignoreAsEquality, ignoreAsContaining, ignoreAsStarting);
    }

    public void setFilterApplyUrls(List<UriFilterOption> filters) {
        clearApplyFilters();
        decomposeFiltersByPurpose(filters, applyFilters, applyAsEquality, applyAsContaining, applyAsStarting);
    }

    private void decomposeFiltersByPurpose(List<UriFilterOption> filters, List<UriFilterOption> allFilters,
                                           Set<UriFilterOption> filtersAsEquality,
                                           Set<UriFilterOption> filtersAsContaining,
                                           Set<UriFilterOption> filtersAsStarting) {
        if (filters != null && !filters.isEmpty()) {
            filters.forEach(f -> {
                if (f.isNotEmpty()){
                    allFilters.add(f);
                }
            });
        }
        for (UriFilterOption filter : filters) {
            final String uri = filter.getUri();
            if (StringUtils.isBlank(uri)) {
                continue;
            }
            if (!uri.contains(WILDCARD_SEARCH_SYMBOL)) {
                filtersAsEquality.add(filter);
            } else {
                final String replaceContainsUri = urlFilterAnalyzer.getApplyAsContainingFilter(uri);
                if (replaceContainsUri != null) {
                    filtersAsContaining.add(new UriFilterOption(replaceContainsUri, filter.getHttpMethod()));
                } else {
                    final String replaceStartsUri = urlFilterAnalyzer.getApplyAsStartingFilter(uri);
                    if (replaceStartsUri != null) {
                        filtersAsStarting.add(new UriFilterOption(replaceStartsUri, filter.getHttpMethod()));
                    } else {
                        filtersAsEquality.add(filter);
                    }
                }
            }
        }
    }

    public boolean isEmpty(){
        return applyPattern == null && applyFilters.isEmpty();
    }

    @Override
    public String toString() {
        StringBuilder filtersBuilder = new StringBuilder();
        filtersBuilder.append("applyFilters=[");
        for (UriFilterOption filter : applyFilters) {
            filtersBuilder.append(filter).append(",");
        }
        filtersBuilder.append("]\n");
        filtersBuilder.append("ignoreFilters=[");
        for (UriFilterOption filter : ignoreFilters) {
            filtersBuilder.append(filter).append(",");
        }

        return "UrlResolver{" +
                "applyPattern=" + applyPattern +
                ", Filter list=" + filtersBuilder.toString() +
                '}';
    }

    private void clearApplyFilters() {
        applyAsEquality.clear();
        applyAsStarting.clear();
        applyAsContaining.clear();

        applyFilters.clear();
    }

    private void clearIgnoreFilters() {
        ignoreAsEquality.clear();
        ignoreAsStarting.clear();
        ignoreAsContaining.clear();

        ignoreFilters.clear();
    }
}
