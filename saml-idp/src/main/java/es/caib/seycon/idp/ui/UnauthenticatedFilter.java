package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class UnauthenticatedFilter implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpSession session = req.getSession();
            session.removeAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
        	session.setAttribute("soffid-session-type", "saml");
        }
        chain.doFilter(request, response);
    }

    public void destroy() {
    }

}
