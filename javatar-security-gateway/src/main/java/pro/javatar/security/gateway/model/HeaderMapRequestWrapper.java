/*
 * Copyright (c) 2018 Javatar LLC
 * All rights reserved.
 */
package pro.javatar.security.gateway.model;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.*;

/**
 * @author Serhii Petrychenko / Javatar LLC
 * @version 09-07-2018
 */
public class HeaderMapRequestWrapper extends HttpServletRequestWrapper {

    private Map<String, String> headerMap = new HashMap<>();

    public HeaderMapRequestWrapper(HttpServletRequest request, Map<String, String> headerMap) {
        super(request);
    }

    public HeaderMapRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    public HeaderMapRequestWrapper(ServletRequest request) {
        super((HttpServletRequest) request);
    }

    public void addHeader(String name, String value) {
        headerMap.put(name, value);
    }

    @Override
    public String getHeader(String name) {
        String headerValue = super.getHeader(name);
        if (headerMap.containsKey(name)) {
            headerValue = headerMap.get(name);
        }
        return headerValue;
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        List<String> names = Collections.list(super.getHeaderNames());
        names.addAll(headerMap.keySet());
        return Collections.enumeration(names);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        List<String> values = Collections.list(super.getHeaders(name));
        if (headerMap.containsKey(name)) {
            values.add(headerMap.get(name));
        }
        return Collections.enumeration(values);
    }

}

