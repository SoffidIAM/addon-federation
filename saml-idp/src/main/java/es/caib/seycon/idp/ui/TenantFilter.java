package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
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

import com.soffid.iam.addons.federation.common.IdpNetworkConfig;
import com.soffid.iam.addons.federation.idp.radius.server.NetmaskMatch;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.broker.SAMLSSOPostServlet;
import es.caib.seycon.idp.ui.broker.SAMLSSORequest;
import es.caib.seycon.ng.exception.InternalErrorException;

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
		
		try {
			IdpConfig config = IdpConfig.getConfig();
			int realPort = request.getLocalPort();
			int port = realPort;
			for (IdpNetworkConfig nc: config.getFederationMember().getNetworkConfig()) {
				if (nc.isProxy() && nc.getPort() == realPort)
				{
					port = nc.getProxyPort();
					if (nc.getProxyInternalAddress() != null && !nc.getProxyInternalAddress().isEmpty()) {
						if (! NetmaskMatch.matches(nc.getProxyInternalAddress(), 
							InetAddress.getByName(req.getRemoteAddr()) ) ) {
							HttpServletResponse r = (HttpServletResponse) response;
							r.setStatus(HttpServletResponse.SC_FORBIDDEN);
							r.setContentType("text/plain");
							r.getOutputStream().println("Forbidden access from "+req.getRemoteAddr());
							r.getOutputStream().close();
							return;
						}
						
					}
					break;
				}
			}
			request = new HttpServletRequestSourceIpWrapper(req, Security.getClientIp(), 
					config.getHostName(), port);
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
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}

	public void destroy() {
	}

}
