package pro.javatar.security.oidc.services;

import pro.javatar.security.oidc.filters.uri.UriFilterOption;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class FilterOptionConverter {

    public List<UriFilterOption> convertList(List<String> list) {
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        return list.stream()
                .map(UriFilterOption::fromString)
                .collect(Collectors.toList());
    }
}
