package pro.javatar.security.oidc;

import pro.javatar.security.oidc.exceptions.AuthenticationException;
import pro.javatar.security.oidc.exceptions.BearerJwtTokenNotFoundAuthenticationException;
import pro.javatar.security.oidc.exceptions.ExchangeTokenByCodeAuthenticationException;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import java.io.IOException;

@Component
public class SecurityTestFilter implements Filter {

    public State state = State.SKIP;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (state == State.FAIL) throw new AuthenticationException();
        if (state == State.BEARER_NOT_FOUND) throw new BearerJwtTokenNotFoundAuthenticationException();
        if (state == State.EXCHANGE_TOKEN_BY_CODE) throw new ExchangeTokenByCodeAuthenticationException();
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}

    public enum State {
        SKIP, FAIL, BEARER_NOT_FOUND, EXCHANGE_TOKEN_BY_CODE
    }
}
