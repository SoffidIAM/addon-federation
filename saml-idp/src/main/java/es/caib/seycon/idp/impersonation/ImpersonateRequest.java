package es.caib.seycon.idp.impersonation;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.ReadListener;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRegistration;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;

import org.eclipse.jetty.servlet.ServletHolder;

public class ImpersonateRequest implements HttpServletRequest {
	Map<String, Object> attributes = new HashMap<>();
	Map<String, String[]> parameters = new HashMap<>();
	Map<String, String> headers = new HashMap<>();
	String encoding = "UTF-8";
	private String contentType;
	URL url;
	ServletContext ctx;
	private String method;
	private ImpersonateSession session;
	private String servletPath;
	private String pathInfo;
	private Set<Cookie> cookies = new HashSet<>();
	
	@Override
	public Object getAttribute(String name) {
		return attributes.get(name);
	}

	@Override
	public Enumeration<String> getAttributeNames() {
		return new Enumeration<String>() {
			Iterator<String> it = attributes.keySet().iterator();
			@Override
			public boolean hasMoreElements() {
				return it.hasNext();
			}

			@Override
			public String nextElement() {
				return it.next();
			}
		};
	}

	@Override
	public String getCharacterEncoding() {
		return encoding;
	}

	@Override
	public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
		this.encoding = env;
	}

	@Override
	public int getContentLength() {
		return 0;
	}

	@Override
	public long getContentLengthLong() {
		return 0;
	}

	@Override
	public String getContentType() {
		return contentType;
	}

	@Override
	public ServletInputStream getInputStream() throws IOException {
		return new ServletInputStream() {
			
			@Override
			public int read() throws IOException {
				return -1;
			}
			
			@Override
			public void setReadListener(ReadListener listener) {
			}
			
			@Override
			public boolean isReady() {
				return false;
			}
			
			@Override
			public boolean isFinished() {
				return true;
			}
		};
	}

	@Override
	public String getParameter(String name) {
		String[] v = parameters.get(name);
		if (v == null || v.length == 0)
			return null;
		else
			return v[0];
	}

	@Override
	public Enumeration<String> getParameterNames() {
		return new Enumeration<String>() {
			Iterator<String> it = parameters.keySet().iterator();
			@Override
			public boolean hasMoreElements() {
				return it.hasNext();
			}

			@Override
			public String nextElement() {
				return it.next();
			}
		};
	}

	@Override
	public String[] getParameterValues(String name) {
		return parameters.get(name);
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		return parameters;
	}

	@Override
	public String getProtocol() {
		return "HTTP/1.1";
	}

	@Override
	public String getScheme() {
		return url.getProtocol();
	}

	@Override
	public String getServerName() {
		return url.getHost();
	}

	@Override
	public int getServerPort() {
		return url.getPort() < 0? url.getDefaultPort(): url.getPort();
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(getInputStream()));
	}

	@Override
	public String getRemoteAddr() {
		return "127.0.0.1";
	}

	@Override
	public String getRemoteHost() {
		return "localhost";
	}

	@Override
	public void setAttribute(String name, Object o) {
		attributes.put(name, o);
	}

	@Override
	public void removeAttribute(String name) {
		attributes.remove(name);
	}

	@Override
	public Locale getLocale() {
		return Locale.getDefault();
	}

	@Override
	public Enumeration<Locale> getLocales() {
		return new Enumeration<Locale>() {
			int pos = 0;
			@Override
			public boolean hasMoreElements() {
				return pos == 0;
			}

			@Override
			public Locale nextElement() {
				pos ++;
				return Locale.getDefault();
			}
		};
	}

	@Override
	public boolean isSecure() {
		return true;
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String path) {
		return ctx.getRequestDispatcher(path);
	}

	@Override
	public String getRealPath(String path) {
		return url.getPath();
	}

	@Override
	public int getRemotePort() {
		return 0;
	}

	@Override
	public String getLocalName() {
		return null;
	}

	@Override
	public String getLocalAddr() {
		return null;
	}

	@Override
	public int getLocalPort() {
		return url.getPort();
	}

	@Override
	public ServletContext getServletContext() {
		return ctx;
	}

	@Override
	public AsyncContext startAsync() throws IllegalStateException {
		return null;
	}

	@Override
	public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
			throws IllegalStateException {
		return null;
	}

	@Override
	public boolean isAsyncStarted() {
		return false;
	}

	@Override
	public boolean isAsyncSupported() {
		return false;
	}

	@Override
	public AsyncContext getAsyncContext() {
		return null;
	}

	@Override
	public DispatcherType getDispatcherType() {
		return DispatcherType.INCLUDE;
	}

	public Map<String, Object> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	public String getEncoding() {
		return encoding;
	}

	public void setEncoding(String encoding) {
		this.encoding = encoding;
	}

	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

	public Map<String, String[]> getParameters() {
		return parameters;
	}

	public void setParameters(Map<String, String[]> parameters) {
		this.parameters = parameters;
	}

	public URL getUrl() {
		return url;
	}

	public void setUrl(URL url) {
		this.url = url;
		calculatePath();
	}

	public ServletContext getCtx() {
		return ctx;
	}

	public void setCtx(ServletContext ctx) {
		this.ctx = ctx;
		calculatePath();
	}

	@Override
	public String getAuthType() {
		return null;
	}

	@Override
	public Cookie[] getCookies() {
		return cookies.toArray(new Cookie[0]);
	}

	@Override
	public long getDateHeader(String name) {
		return 0;
	}

	@Override
	public String getHeader(String name) {
		return headers.get(name);
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
		return new Enumeration<String>() {
			boolean first = true;
			@Override
			public boolean hasMoreElements() {
				return first && headers.containsKey(name);
			}

			@Override
			public String nextElement() {
				first = false;
				return headers.get(name);
			}
		};
	}

	@Override
	public Enumeration<String> getHeaderNames() {
		return new Enumeration<String>() {
			Iterator<String> iterator = headers.keySet().iterator();
			@Override
			public boolean hasMoreElements() {
				return iterator.hasNext();
			}

			@Override
			public String nextElement() {
				return iterator.next();
			}
		};
	}

	@Override
	public int getIntHeader(String name) {
		return 0;
	}

	@Override
	public String getMethod() {
		return method;
	}

	@Override
	public String getPathInfo() {
		return pathInfo;
	}

	@Override
	public String getPathTranslated() {
		return null;
	}

	@Override
	public String getContextPath() {
		return "";
	}

	@Override
	public String getQueryString() {
		return url.getQuery();
	}

	@Override
	public String getRemoteUser() {
		return null;
	}

	@Override
	public boolean isUserInRole(String role) {
		return false;
	}

	@Override
	public Principal getUserPrincipal() {
		return null;
	}

	@Override
	public String getRequestedSessionId() {
		return "dummy";
	}

	@Override
	public String getRequestURI() {
		return url.getPath();
	}

	@Override
	public StringBuffer getRequestURL() {
		return new StringBuffer(url.getProtocol()+"://"+url.getHost()+
				(url.getPort() >= 0 ? ":"+Integer.toString(url.getPort()): "")+
				url.getPath());
	}

	@Override
	public String getServletPath() {
		return servletPath;
	}

	@Override
	public HttpSession getSession(boolean create) {
		if (session == null && create) {
			session = new ImpersonateSession();
			session.setContext(ctx);
		}
		return session;
	}

	@Override
	public HttpSession getSession() {
		return getSession(true);
	}

	@Override
	public String changeSessionId() {
		return "dummy";
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return true;
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return true;
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return false;
	}

	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return false;
	}

	@Override
	public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
		return false;
	}

	@Override
	public void login(String username, String password) throws ServletException {
	}

	@Override
	public void logout() throws ServletException {
	}

	@Override
	public Collection<Part> getParts() throws IOException, ServletException {
		return null;
	}

	@Override
	public Part getPart(String name) throws IOException, ServletException {
		return null;
	}

	@Override
	public <T extends HttpUpgradeHandler> T upgrade(Class<T> httpUpgradeHandlerClass)
			throws IOException, ServletException {
		return null;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	private void calculatePath() {
		if (ctx == null || url == null)
			return;
		servletPath = "";
		pathInfo = url.getPath();
		int matchLength = 0;
		Map<String, ? extends ServletRegistration> servlets = ctx.getServletRegistrations();
		for (Object o: servlets.values()) {
			ServletHolder.Registration r = (ServletHolder.Registration) o;
			Collection<String> mappings = r.getMappings();
			for (String map: mappings) {
				String map2 = "^"+map.replace("?", ".?").replace("*", ".*")+"$";
				if (Pattern.matches(map2, url.getPath()) && map.length() > matchLength) {
					if (map.endsWith("/*")) {
						matchLength = map.length()-2;
						pathInfo = url.getPath().substring(matchLength);
						servletPath = url.getPath().substring(0, matchLength);
					}
					else {
						matchLength = map.length();
						servletPath = "";
						pathInfo = url.getPath();
					}
				}
			}
		}

	}

	public void setSession(ImpersonateSession session) {
		this.session = session;
	}

	public void addCookie(Cookie cookie) {
		cookies.add(cookie);
	}
}
