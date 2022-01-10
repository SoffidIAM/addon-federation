package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

public class TenantFilter implements Filter {
	Log log = LogFactory.getLog(getClass());
	
	private FilterConfig filterConfig;

	public void init(FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		final HttpServletRequest req = (HttpServletRequest) request;
		log.info( "TRUSTED - IPS: "+System.getProperty("soffid.proxy.trustedIps") );
		log.info( "X-Forwaded-for:"+req.getHeader("x-forwarded-for"));
		log.info( "Source        :"+req.getRemoteAddr());
		Security.setClientRequest(req);
		log.info( "Result        :"+Security.getClientIp());
		request = new HttpServletRequestSourceIpWrapper(req, Security.getClientIp());
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
