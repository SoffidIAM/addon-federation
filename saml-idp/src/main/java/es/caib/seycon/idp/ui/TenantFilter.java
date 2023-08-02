package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.ServletRequestHttpWrapper;

import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.ui.broker.SAMLSSOPostServlet;
import es.caib.seycon.idp.ui.broker.SAMLSSORequest;

public class TenantFilter implements Filter {
	Log log = LogFactory.getLog(getClass());
	
	private FilterConfig filterConfig;

	public void init(FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		final HttpServletResponse res = (HttpServletResponse) response;
		final HttpServletRequest req = (HttpServletRequest) request;
		Security.setClientRequest(req);
		String uri = req.getContextPath()+req.getServletPath();
		if (req.getPathInfo() != null)
			uri += req.getPathInfo();
		int port = Integer.parseInt(filterConfig.getInitParameter("port"));
		String host = filterConfig.getInitParameter("host");
		request = new HttpServletRequestSourceIpWrapper(req, Security.getClientIp(), host, port);
		String tenant = filterConfig.getInitParameter("tenant");
		if (tenant != null)
		{
			Security.nestedLogin(tenant, "anonymous", new String [0]);
			try {
				chain.doFilter(request, response);
			} finally {
				Security.nestedLogoff();
			}
		}
		else
			chain.doFilter(request, response);
	}

	public void destroy() {
	}

}
