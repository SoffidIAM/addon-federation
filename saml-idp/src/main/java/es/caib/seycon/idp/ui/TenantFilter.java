package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import com.soffid.iam.utils.Security;

public class TenantFilter implements Filter {

	private FilterConfig filterConfig;

	public void init(FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
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
