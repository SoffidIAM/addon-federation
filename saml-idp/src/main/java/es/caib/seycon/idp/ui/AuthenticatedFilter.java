package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;

public class AuthenticatedFilter implements Filter {


    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest req = (HttpServletRequest) request;

            StringBuffer path = new StringBuffer(req.getRequestURI());
            if (req.getQueryString() != null) {
                path.append ("?"); //$NON-NLS-1$
                path.append (req.getQueryString());
            }
            
            HttpSession session = req.getSession();
            String userId = (String) session.getAttribute(SessionConstants.SEU_USER);
            if (userId == null) {
            	session.removeAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
            	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, "anonymous"); //$NON-NLS-1$
            	session.setAttribute(HtmlGenerator.ORGANIZATION_URL, req.getRequestURL().toString());
            	session.setAttribute(HtmlGenerator.ORGANIZATION_NAME, Messages.getString("AuthenticatedFilter.2")); //$NON-NLS-1$
            	session.setAttribute(SessionConstants.AUTHENTICATION_REDIRECT, path.toString());
            	((HttpServletResponse) response).sendRedirect(LoginServlet.URI);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    public void destroy() {
    }

}
