package pro.javatar.security.starter.config.model;

import pro.javatar.security.api.config.SecurityConfig;

import java.util.List;

/**
 * @author Borys Zora
 * @version 2019-06-14
 */
public class HttpClientImpl implements SecurityConfig.HttpClient {

    List<String> applyUrls;

    List<String> ignoreUrls;

    @Override
    public List<String> applyUrls() {
        return applyUrls;
    }

    @Override
    public List<String> ignoreUrls() {
        return ignoreUrls;
    }

    public void setApplyUrls(List<String> applyUrls) {
        this.applyUrls = applyUrls;
    }

    public void setIgnoreUrls(List<String> ignoreUrls) {
        this.ignoreUrls = ignoreUrls;
    }

    @Override
    public String toString() {
        return "HttpClientImpl{" +
                "applyUrls=" + applyUrls +
                ", ignoreUrls=" + ignoreUrls +
                '}';
    }
}