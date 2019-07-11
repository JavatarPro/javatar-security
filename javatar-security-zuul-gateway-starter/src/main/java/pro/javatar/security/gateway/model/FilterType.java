package pro.javatar.security.gateway.model;

public enum FilterType {

    PRE("pre"),
    ROUTE("route"),
    ERROR("error"),
    POST("post");

    private String text;

    FilterType(String text) {
        this.text = text;
    }

    public String asText() {
        return text;
    }
}
