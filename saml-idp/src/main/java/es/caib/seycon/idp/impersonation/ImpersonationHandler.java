package es.caib.seycon.idp.impersonation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterConfig;
import javax.servlet.FilterRegistration;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.ui.AuthenticatedFilter;
import es.caib.seycon.idp.ui.P3PFilter;
import es.caib.seycon.idp.ui.UnauthenticatedFilter;

public class ImpersonationHandler {
	private final class DummyFilterConfig implements FilterConfig {
		@Override
		public ServletContext getServletContext() { return ctx;	}

		@Override
		public Enumeration<String> getInitParameterNames() {
			return new Enumeration<String>() {
				public boolean hasMoreElements() { return false;}
				public String nextElement() { return null;}
			};
		}

		@Override
		public String getInitParameter(String name) { return null; }

		@Override
		public String getFilterName() {	return null;}
	}

	private String url;
	private TokenInfo token;
	private IdpConfig config;
	private boolean saml;
	private ServletContext ctx;
	List<HttpCookie> serverCookies = new LinkedList<>();
	List<HttpCookie> internalCookies = new LinkedList<>();
	int retries = 0;
	ImpersonateSession session = new ImpersonateSession();

	public void impersonate (ServletContext ctx, String url, TokenInfo ti) throws Exception {
		config = IdpConfig.getConfig();
		this.url = url;
		this.ctx = ctx;
		this.token = ti;
		readInitialUrl();
	}

	private void readInitialUrl() throws IOException, ServletException {
		URL url = new URL(this.url);
		processServerUrl(url, null, true);
	}

	private void processServerUrl(URL url, String formData, boolean processForm) throws IOException, ServletException {
		checkRedirectLoop(url);
		HttpURLConnection c = (HttpURLConnection) url.openConnection();
		c.setInstanceFollowRedirects(false);
		c.setDoInput(true);
		if (formData == null)
			c.setDoOutput(false);
		else
			c.setDoOutput(true);
		setCookies(c, url.getHost());
		if (formData != null) {
			c.setRequestMethod("POST");
			c.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			OutputStream out = c.getOutputStream();
			out.write(formData.getBytes("UTF-8"));
			out.close();
		}
		c.connect();
		byte data[] = readConnection(c);
		try {
			if (c.getResponseCode() == 302) // Redirect 
			{
				URL target = getTargetLocation(url, c.getHeaderField("Location"));
				if (isInternalRequest(target)) {
					processInternalRequest(target, parseParams(target), "GET");
				} else {
					processServerUrl(target, null, processForm);
				}
			} else if (processForm) {
				processForm(url, data, null);
			}
		} finally {
			c.disconnect();
		}
	}

	public boolean isInternalRequest(URL target) {
		if ( target.getHost().equals(config.getHostName())) {
			int port = target.getPort();
			if (port < 0) port = target.getDefaultPort();
			if (port == config.getStandardPort() || port == config.getClientCertPort())
				return true;
		}
		return false;
	}

	public URL getTargetLocation(URL url, String header) throws MalformedURLException {
		if (! header.startsWith("http://") && ! header.startsWith("https://")) {
			if (header.startsWith("/"))
				header = url.getProtocol()+"://"+url.getHost()+(url.getPort() < 0 ? "": ":"+url.getPort())+header;
			else
			{
				String path = url.toString();
				int i = path.lastIndexOf("/");
				if (i >= 0) path = path.substring(0, i);
				header = path + header;
			}
		}
		URL target = new URL(header);
		return target;
	}

	private void setCookies(HttpURLConnection c, String host) {
		StringBuffer sb = new StringBuffer();
		for (HttpCookie cookie: serverCookies) {
			if ( host.endsWith( cookie.getDomain()))
				sb.append(cookie.getName())
					.append("=")
					.append(cookie.getValue())
					.append("; ");
		}
		if (sb.length() > 0)
			c.setRequestProperty("Cookie", sb.toString());
	}

	private byte[] readConnection(HttpURLConnection c) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		InputStream in = c.getInputStream();
		for (int i = in.read(); i >= 0; i = in.read())
			buffer.write(i);
		Map<String, List<String>> headers = c.getHeaderFields();
		for (String key: headers.keySet()) {
			if ("set-cookie".equalsIgnoreCase(key)) {
				for (String v: headers.get(key)) {
					for (HttpCookie cookie: HttpCookie.parse(v)) {
						if (cookie.getDomain() == null)
							cookie.setDomain(c.getURL().getHost());
						for (Iterator<HttpCookie> it = serverCookies.iterator(); it.hasNext();) {
							HttpCookie sc = it.next();
							if (sc.getName().equals(cookie.getName()) &&
									sc.getDomain().equals(cookie.getDomain()))
								it.remove();
						}
						if (! cookie.getDiscard() && cookie.getMaxAge() != 0) {
							serverCookies.add(cookie);
						}
					}
				}
			}
		}
		return buffer.toByteArray();
	}

	private Map<String, String[]> parseParams(URL target) throws UnsupportedEncodingException {
		HashMap<String, String[]> m = new HashMap<>();
		if (target.getQuery() != null) {
			for (String part: target.getQuery().split("&")) {
				int i = part.indexOf('=');
				String name;
				String value;
				if (i >= 0) {
					name = part.substring(0, i);
					value = part.substring(i+1);
				} else {
					name = part;
					value = "";
				}
				name = URLDecoder.decode(name, "UTF-8");
				value = URLDecoder.decode(value, "UTF-8");
				String[] old = m.get(name);
				if (old == null) m.put(name, new String[] {value});
				else {
					String[] newArray = new String[old.length+1];
					for (int j = 0; j < old.length; j++) newArray[j] = old[j];
					newArray[old.length] = value;
					m.put(name, newArray);
				}
			}
		}
		return m;
	}

	private void processInternalRequest(URL target, Map<String, String[]> map, String method) throws ServletException, IOException {
		RequestDispatcher d = ctx.getRequestDispatcher(target.getPath());
		ImpersonateRequest request = new ImpersonateRequest();
		request.setAttribute("$$internaltoken$$", token);
		request.setCharacterEncoding("UTF-8");
		request.setCtx(ctx);
		request.setParameters(map);
		request.setMethod(method);
		request.setUrl(target);
		session.setContext(ctx);
		request.setSession(session);
		if (session.getAttribute("soffid-session-type") == null) {
			if (target.getPath().contains("profile/SAML2")) {
				saml = true;
				request.getSession().setAttribute("soffid-session-type", "saml");
			} else {
				saml = false;
				request.getSession().setAttribute("soffid-session-type", "openid");
			}
		}
		setCookies(request, config.getHostName());
		ImpersonateResponse response = new ImpersonateResponse();
		// Create the filter chain
		ImpersonationFilterChain chain = new ImpersonationFilterChain(d);
		chain.addFilter(new P3PFilter());
		chain.addFilter(new edu.internet2.middleware.shibboleth.common.log.SLF4JMDCCleanupFilter());
		edu.internet2.middleware.shibboleth.idp.session.IdPSessionFilter sessionFilter = new edu.internet2.middleware.shibboleth.idp.session.IdPSessionFilter();
		sessionFilter.init(new DummyFilterConfig());
		chain.addFilter(sessionFilter);
		if (target.getPath().startsWith("/protected"))
			chain.addFilter(new AuthenticatedFilter());
		if (target.getPath().startsWith("/profile"))
		chain.addFilter(new UnauthenticatedFilter());
		chain.doFilter(request, response);
		processLoginResponse (target, response);
	}

	private void processLoginResponse(URL url, ImpersonateResponse response) throws UnsupportedEncodingException, ServletException, IOException {
		checkRedirectLoop(url);
		
		for (Cookie c: response.getCookies()) {
			HttpCookie cookie = new HttpCookie(c.getName(), c.getValue());
			internalCookies.add(cookie);
		}

		if (response.getStatus() == 302) // Redirect 
		{
			processLoginRedirect(url, response);
		} else {
			processForm(url, response.getOut().toByteArray(), response.getCharacterEncoding());
		}
	}

	private void setCookies(ImpersonateRequest r, String host) {
		StringBuffer sb = new StringBuffer();
		for (HttpCookie cookie: internalCookies) {
			r.addCookie(new Cookie(cookie.getName(),cookie.getValue()));
		}
	}
	
	public void processLoginRedirect(URL url, ImpersonateResponse response)
			throws MalformedURLException, ServletException, IOException, UnsupportedEncodingException {
		URL target;
		target = getTargetLocation(url, response.getHeader("Location"));
		if (isInternalRequest(target)) {
			processInternalRequest(target, parseParams(target), "GET");
		} else {
			processServerUrl(url, null, false);
		}
	}

	private void processForm(URL url, byte[] response, String encoding) throws IOException, ServletException {
		if (encoding == null)
			encoding = "UTF-8";
		ByteArrayInputStream in = new ByteArrayInputStream(response);
		Document doc = Jsoup.parse( in, encoding, url.toString());
		Elements forms = doc.getElementsByTag("form");
		if (forms.size() != 1) {
			throw new IOException("Expecting a form, but no form found on "+new String(response, encoding));
		}
		Element form = forms.get(0);
		Elements inputs = form.getElementsByTag("input");
		StringBuffer sb = new StringBuffer();
		Map<String, String[]> params = new HashMap<>();
		for (int i = 0; i < inputs.size(); i++) {
			Element input = inputs.get(i);
			String name = input.attr("name");
			String value = input.attr("value");
			if (name != null && value != null) {
				params.put(name, new String[] { value });
				if (sb.length() > 0) sb.append("&");
				sb.append(URLEncoder.encode(name))
					.append("=")
					.append(URLEncoder.encode(value));
			}
		}
		String action = form.absUrl("action");
		URL actionUrl = new URL(action);
		if (isInternalRequest(actionUrl))
			processInternalRequest(actionUrl, params, "POST");
		else
			processServerUrl(actionUrl, sb.toString(), false);
	}

	public void checkRedirectLoop(URL target) throws IOException {
		retries ++;
		if (retries > 20)
			throw new IOException("Too much redirections "+target.toString());
	}

	public List<HttpCookie> getServerCookies() {
		return serverCookies;
	}
}
