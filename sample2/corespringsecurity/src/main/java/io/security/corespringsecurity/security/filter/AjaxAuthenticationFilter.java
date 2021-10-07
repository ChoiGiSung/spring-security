package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper mapper = new ObjectMapper();

    public AjaxAuthenticationFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {

        if(isAjax(httpServletRequest)){
            throw new IllegalStateException("no Ajax");
        }

        AccountDto accountDto = mapper.readValue(httpServletRequest.getReader(), AccountDto.class);

        if(StringUtils.isEmpty(accountDto.getUserName()) || StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("Empty");
        }

        AjaxAuthenticationToken token = new AjaxAuthenticationToken(accountDto.getUserName(),accountDto.getPassword());

        return getAuthenticationManager().authenticate(token);
    }

    private boolean isAjax(HttpServletRequest httpServletRequest) {

        if("XMLHttpRequest".equals(httpServletRequest.getHeader("X-Requested-With"))){
            return true;
        }

        return false;
    }
}
